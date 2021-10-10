package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/phayes/freeport"

	"github.com/gruntwork-io/terratest/modules/docker"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/shell"
	"github.com/gruntwork-io/terratest/modules/testing"

	vault "github.com/hashicorp/vault/api"
)

var (
	binPath string

	// IgnoreTLS prevents the vault client from checking for TLS stuff
	IgnoreTLS []string
)

const (
	rootVaultToken = "OTY1MEZENUQtRkQ2Ri00MjlFLThFNTktMTFCOTdDQTE1NjU3Cg="
	policyFile     = "policy.hcl"
)

type appRole struct {
	RoleID   string
	SecretID string
}

// TestVault manages the temporary vault container
type TestVault struct {
	Client *vault.Client
	State  States
	t      testing.TestingT
	name   string
	appRole
}

// States are the various states that the dev vault module can be in
type States int

// States that the test vault can be in during testing. These are set at various points of execution.
const (
	Starting States = iota
	Initializing
	Ready
	Stoping
	Finished
	Error
	Failed
	Aborted
	Fatal
)

// Setup runs a memory only development version which is perfect for tests. It will run on any free
// port on the host, so you can run multiple instances of the test(s) without colliding.
func Setup() (*TestVault, error) {
	vaultPort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}
	v := &TestVault{
		name:  fmt.Sprintf("terraform-vault-%d", vaultPort),
		State: Starting,
	}
	runOpts := &docker.RunOptions{
		Detach: true,
		EnvironmentVariables: []string{
			fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", rootVaultToken),
			"VAULT_SKIP_VERIFY=true",
		},
		Name: v.name,
		OtherOptions: []string{
			"--cap-add=IPC_LOCK", "-p",
			fmt.Sprintf("%d:8200", vaultPort),
		},
		Remove: true,
		Logger: logger.Default,
	}
	containerID := docker.Run(v.t, "vault", runOpts)
	var key string
	if key, err = getUnsealKey(v, containerID, vaultPort); err != nil {
		v.Fatalf("Starting Fatality: %s", err.Error())
		return v, err
	}

	vConfig := vault.DefaultConfig()
	vConfig.Address = fmt.Sprintf("http://127.0.0.1:%d", vaultPort)
	if err = vConfig.ConfigureTLS(&vault.TLSConfig{Insecure: true}); err != nil {
		v.Errorf("Error Configuring Vault Client: %s", err.Error())
		return v, err
	}
	if v.Client, err = vault.NewClient(vConfig); err != nil {
		v.Fatalf("Unable to create a vault client: %s", err.Error())
		return v, err
	}

	if err = v.unseal(key); err != nil {
		v.Fatalf("Unable to unseal vault: %s", err.Error())
		return v, err
	}

	if err = v.enableAuth(); err != nil {
		v.FailNow()
		return v, err
	}

	v.State = Initializing
	v.createPolicyAndRole()
	v.State = Ready
	return v, nil
}

func getUnsealKey(t testing.TestingT, containerID string, port int) (string, error) {
	unsealKeyRE := regexp.MustCompile("^Unseal Key: (.*)$")
	logOutoutCmd := shell.Command{
		Command: "docker",
		Args:    []string{"logs", "-n", "10", containerID},
		Logger:  logger.Default,
	}
	output := shell.RunCommandAndGetOutput(t, logOutoutCmd)

	if match := unsealKeyRE.FindStringSubmatch(output); match != nil {
		logger.Logf(t, "Found the Vault unseal key, proceeding to unseal")
		return match[1], nil
	}
	return "", errors.New("Unable to determine the Vault unseal key, aborting")
}

func (v *TestVault) unseal(key string) error {
	sys := v.Client.Sys()
	unsealResponse, err := sys.Unseal(key)
	if err != nil {
		return err
	}
	if unsealResponse.Sealed {
		return errors.New("Vault is still sealed")
	}
	return nil
}

func (v *TestVault) enableAuth() error {
	sys := v.Client.Sys()
	options := &vault.EnableAuthOptions{Type: "approle"}
	if err := sys.EnableAuthWithOptions("auth/approle", options); err != nil {
		return err
	}

	options = &vault.EnableAuthOptions{Type: "kubernetes"}
	return sys.EnableAuthWithOptions("", options)
}

// This will create the policy which will allow the test to perform the creation of roles in the
// test vault.
func (v *TestVault) createPolicyAndRole() {
	IgnoreTLS = []string{"-tls-skip-verify", "-address", v.Client.Address()}
	vaultCmd := shell.Command{
		Command: binPath,
		Env: map[string]string{
			"VAULT_TOKEN": rootVaultToken,
		},
		Logger: logger.Default,
	}

	vaultCmd.Args = append([]string{"policy", "write", "cicd", policyFile}, IgnoreTLS...)
	shell.RunCommand(v.t, vaultCmd)

	vaultCmd.Args = append([]string{"write", "auth/approle/role/terratest", "policies=cicd"}, IgnoreTLS...)
	shell.RunCommand(v.t, vaultCmd)

	var err error
	var tmpVal interface{}
	vaultCmd.Args = append([]string{"read", "auth/approle/role/terratest/role-id", "-format=json"}, IgnoreTLS...)
	if tmpVal, err = GetVaultValue(v.t, vaultCmd, "role_id"); err != nil {
		panic(err)
	}
	v.RoleID = reflect.ValueOf(tmpVal).String()

	vaultCmd.Args = append([]string{"write", "-f", "auth/approle/role/terratest/secret-id", "-format=json"},
		IgnoreTLS...)
	if tmpVal, err = GetVaultValue(v.t, vaultCmd, "secret_id"); err != nil {
		panic(err)
	}
	v.SecretID = reflect.ValueOf(tmpVal).String()
}

// GetVaultValue will execute on the command you give it and then return the value of the data.
func GetVaultValue(t testing.TestingT, cmd shell.Command, key string) (interface{}, error) {
	type response struct {
		Data  map[string]interface{} `json:"data"`
		Other map[string]interface{} `json:"-"`
	}

	vr := new(response)
	buf := bytes.NewBufferString(shell.RunCommandAndGetStdOut(t, cmd))
	if err := json.Unmarshal(buf.Bytes(), vr); err != nil {
		logger.Logf(t, "Unable to parse the Vault response for the %s", key)
		return nil, err
	}
	return vr.Data[key], nil
}

//func init() {
//	var err error
//	binPath, err = exec.LookPath("vault")
//	if err != nil {
//		panic("Unable to locate the vault binary")
//	}
//}

// Stop will tell the docker container to quit. It should clean up on it's own.
func (v *TestVault) Stop() {
	v.State = Stoping
	findVault := shell.Command{
		Command: "docker",
		Args:    []string{"ps", "--filter", fmt.Sprintf("name=%s", v.name), "-q"},
		Logger:  logger.Default,
	}
	container := shell.RunCommandAndGetStdOut(v.t, findVault)
	if container == "" {
		logger.Logf(v.t, "No container found with the name %s", v.name)
		return
	}

	stopOpts := &docker.StopOptions{}
	docker.Stop(v, []string{container}, stopOpts)
}

// Fail interface methods to have TestVault satisfy the terratest testing.TestingT interface
func (v TestVault) Fail() {
	logger.Default.Logf(v, "Test Vault %s is in a Failed state", v.Name())
	v.State = Failed
}

// FailNow fails immediately
func (v TestVault) FailNow() {
	v.State = Aborted
}

// Fatal is just your standard message
func (v TestVault) Fatal(args ...interface{}) {
	v.State = Fatal
}

// Fatalf has args you can pass in
func (v TestVault) Fatalf(format string, args ...interface{}) {
	v.State = Fatal
}

// Error is just that, an error
func (v TestVault) Error(args ...interface{}) {
	v.State = Error
}

// Errorf has args
func (v TestVault) Errorf(format string, args ...interface{}) {
	v.State = Error
}

// Name returns the name of the vault instance you have running
func (v TestVault) Name() string {
	return v.name
}
