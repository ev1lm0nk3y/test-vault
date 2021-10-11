package vault

/*
This package deploys a dev vault instance in docker so that we can perform operations on it
*/

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"time"

	"github.com/phayes/freeport"

	"github.com/gruntwork-io/terratest/modules/docker"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/retry"
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

// AppRole is a holder for the vault approle credentials
type AppRole struct {
	RoleID   string
	SecretID string
}

// TestVault manages the temporary vault container
type TestVault struct {
	Client      *vault.Client
	State       States
	name        string
	containerID string
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
			"VAULT_API_ADDR=http://127.0.0.1:8200",
		},
		Name: v.name,
		OtherOptions: []string{
			"--cap-add=IPC_LOCK", "-p",
			fmt.Sprintf("%d:8200", vaultPort),
		},
		Remove: true,
		Logger: logger.Discard,
	}
	v.containerID = docker.Run(v, "vault", runOpts)
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
	IgnoreTLS = []string{"-tls-skip-verify", "-address", v.Client.Address()}

	v.State = Ready
	return v, nil
}

// Unseal Vault
func (v *TestVault) Unseal() error {
	key, err := v.getUnsealKey()
	if err == nil {
		v.Fatal(err.Error())
	}
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

func (v *TestVault) getUnsealKey() (string, error) {
	unsealKeyRE := regexp.MustCompile("Unseal Key: (.*)")
	logOutoutCmd := shell.Command{
		Command: "docker",
		Args:    []string{"logs", v.containerID},
		Logger:  logger.Discard,
	}
	return retry.DoWithRetryE(v, "Read Vault Startup Logs", 10, 3*time.Second, func() (string, error) {
		output := shell.RunCommandAndGetStdOut(v, logOutoutCmd)

		if match := unsealKeyRE.FindStringSubmatch(output); match != nil {
			logger.Default.Logf(v, "Found the Vault unseal key, proceeding to unseal")
			return match[1], nil
		}
		return "",
			fmt.Errorf("Unable to determine the Vault unseal key. Retrying")
	})
}

// EnableAuth allows you to enable any Vault auth mechanism. options can be nil as the default is "auth/<authType>"
func (v *TestVault) EnableAuth(authType string, options *vault.EnableAuthOptions) error {
	sys := v.Client.Sys()
	if options == nil {
		options = &vault.EnableAuthOptions{Type: authType}
	}
	return sys.EnableAuthWithOptions(fmt.Sprintf("auth/%s", authType), options)
}

// CreateAppRoleWithPolicy will create the policy and then attqch your role to it
// If any of the commands fail, Terratest will gently exit the test run.
func (v *TestVault) CreateAppRoleWithPolicy(policyName, policyFile, roleName string) AppRole {
	vaultCmd := shell.Command{
		Command: binPath,
		Env: map[string]string{
			"VAULT_TOKEN": rootVaultToken,
		},
		Logger: logger.Default,
	}

	policyCmd := []string{"policy", "write", policyName, policyFile}
	vaultCmd.Args = append(policyCmd, IgnoreTLS...)
	shell.RunCommand(v, vaultCmd)

	roleCmd := []string{"write", fmt.Sprintf("auth/approle/role/%s", roleName),
		fmt.Sprintf("policies=%s", policyName)}
	vaultCmd.Args = append(roleCmd, IgnoreTLS...)
	shell.RunCommand(v, vaultCmd)

	var ar AppRole
	var err error
	var tmpVal interface{}
	vaultCmd.Args = append([]string{"read", fmt.Sprintf("auth/approle/role/%s/role-id", roleName), "-format=json"}, IgnoreTLS...)
	if tmpVal, err = GetVaultValues(v, vaultCmd, "role_id"); err != nil {
		v.Fatal(err)
		return ar
	}
	ar.RoleID = reflect.ValueOf(tmpVal).String()

	vaultCmd.Args = append([]string{"write", "-f", fmt.Sprintf("auth/approle/role/%s/secret-id", roleName), "-format=json"},
		IgnoreTLS...)
	if tmpVal, err = GetVaultValues(v, vaultCmd, "secret_id"); err != nil {
		log.Fatal(err)
	}
	ar.SecretID = reflect.ValueOf(tmpVal).String()
	return ar
}

// GetVaultValues will execute on the command you give it and then return the value of the data that you specified.
func GetVaultValues(t testing.TestingT, cmd shell.Command, keys ...string) (map[string]interface{}, error) {
	type response struct {
		Data  map[string]interface{} `json:"data"`
		Other map[string]interface{} `json:"-"`
	}

	vr := new(response)
	buf := bytes.NewBufferString(shell.RunCommandAndGetStdOut(t, cmd))
	if err := json.Unmarshal(buf.Bytes(), vr); err != nil {
		logger.Logf(t, "Unable to parse the Vault response while fetching the data")
		return nil, err
	}
	var retval map[string]interface{}
	for _, key := range keys {
		retval[key] = vr.Data[key]
	}
	return retval, nil
}

// Stop will tell the docker container to quit. It should clean up on it's own.
func (v *TestVault) Stop() {
	v.State = Stoping
	findVault := shell.Command{
		Command: "docker",
		Args:    []string{"ps", "--filter", fmt.Sprintf("name=%s", v.name), "-q"},
		Logger:  logger.Default,
	}
	container := shell.RunCommandAndGetStdOut(v, findVault)
	if container == "" {
		logger.Logf(v, "No container found with the name %s", v.name)
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
	log.Fatal(args...)
}

// Fatalf has args you can pass in
func (v TestVault) Fatalf(format string, args ...interface{}) {
	v.State = Fatal
	log.Fatalf(format, args...)
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
