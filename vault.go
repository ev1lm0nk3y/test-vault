package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/phayes/freeport"

	"github.com/gruntwork-io/terratest/modules/docker"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/shell"

	vault "github.com/hashicorp/vault/api"
)

var (
	logs    = logger.New()
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
	t      *testing.T
	name   string
	appRole
}

// Setup runs a memory only development version which is perfect for tests. It will run on any free
// port on the host, so you can run multiple instances of the test(s) without colliding.
func Setup(t *testing.T) (*TestVault, error) {
	vaultPort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}
	v := &TestVault{
		name: fmt.Sprintf("terraform-vault-%d", vaultPort),
		t:    t,
	}
	runOpts := &docker.RunOptions{
		Detach: true,
		EnvironmentVariables: []string{
			fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%d", rootVaultToken),
			"VAULT_SKIP_VERIFY=true",
		},
		Name: v.name,
		OtherOptions: []string{
			"--cap-add=IPC_LOCK",
			fmt.Sprintf("--port=%d:8200", vaultPort),
		},
		Remove: true,
		Logger: logs,
	}
	vaultStartLogs := docker.Run(t, "vault", runOpts)

	unsealKeyRE := regexp.MustCompile("^Unseal Key: (.*)$")
	var unsealKey string
	match := unsealKeyRE.FindStringSubmatch(vaultStartLogs)
	if match == nil {
		return v, errors.New("Unable to determine the Vault unseal key, aborting")
	}
	unsealKey = match[1]
	logger.Logf(t, "Found the Vault unseal key, proceeding to unseal")

	vConfig := vault.DefaultConfig()
	vConfig.Address = fmt.Sprintf("http://127.0.0.1:%d", vaultPort)
	if err = vConfig.ConfigureTLS(&vault.TLSConfig{Insecure: true}); err != nil {
		return v, err
	}
	if v.Client, err = vault.NewClient(vConfig); err != nil {
		return v, err
	}

	if err = v.unsealVault(unsealKey); err != nil {
		return v, err
	}

	if err = v.enableAuth(); err != nil {
		return v, err
	}

	v.createPolicyAndRole()
	return v, err
}

func (v *TestVault) unsealVault(key string) error {
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
		Logger: logs,
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
func GetVaultValue(t *testing.T, cmd shell.Command, key string) (interface{}, error) {
	var vr struct {
		Data map[string]interface{} `json=data`
	}
	buf := bytes.NewBufferString(shell.RunCommandAndGetStdOut(t, cmd))
	if err := json.Unmarshal(buf.Bytes(), vr); err != nil {
		logs.Logf(t, "Unable to parse the Vault response for the {}", key)
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
	findVault := shell.Command{
		Command: "docker",
		Args:    []string{"ps", "--filter", fmt.Sprintf("name={}", v.name), "-q"},
	}
	container := shell.RunCommandAndGetStdOut(v.t, findVault)
	if container == "" {
		logs.Logf(v.t, "No container found with the name {}", v.name)
		return
	}

	stopOpts := &docker.StopOptions{}
	docker.Stop(v.t, []string{container}, stopOpts)
}
