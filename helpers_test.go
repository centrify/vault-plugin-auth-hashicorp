package centrify //nolint: testpackage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	vltBin         = "vault"
	vltAddrEnv     = "VAULT_ADDR"
	vltTokenEnv    = "VAULT_TOKEN"
	vltDefaultAddr = "http://127.0.0.1:8200"
	vltHeaderToken = "X-Vault-Token" //nolint: gosec
)

// cliVault runs Vault CLI with given arguments.
func cliVault(t *testing.T, token string, arg ...string) (stdout []byte) {
	t.Helper()

	vlt := exec.Command(vltBin, arg...)

	vlt.Env = os.Environ()

	if _, ok := os.LookupEnv(vltAddrEnv); !ok {
		t.Logf("%q is not set. Setting it to default %q", vltAddrEnv, vltDefaultAddr)
		vlt.Env = append(vlt.Env, fmt.Sprintf("%s=%s", vltAddrEnv, vltDefaultAddr))
	}
	if token != "" {
		vlt.Env = append(vlt.Env, fmt.Sprintf("%s=%s", vltTokenEnv, token))
	}

	var bStdout, bStderr bytes.Buffer
	vlt.Stdout = &bStdout
	vlt.Stderr = &bStderr

	if err := vlt.Run(); err != nil {
		fullCmd := strings.Join(vlt.Args, " ")

		if bStdout.Len() != 0 {
			t.Fatalf("Failed to exec %q\n\tstdout:\n%s\n\tstderr:\n%s",
				fullCmd, bStdout.String(), bStderr.String())
		} else {
			t.Fatalf("Failed to exec %q\n\tstderr:\n%s", fullCmd, bStderr.String())
		}
	}

	return bStdout.Bytes()
}

// cliVaultLogin performs login and returns token.
func cliVaultLogin(t *testing.T, arg ...string) (token string) {
	t.Helper()

	arg = append(
		[]string{"login", "-format=json", "-no-store=true", "-token-only"},
		arg...,
	)
	vlt := exec.Command(vltBin, arg...)

	if _, ok := os.LookupEnv(vltAddrEnv); !ok {
		t.Logf("%q is not set. Setting it to default %q", vltAddrEnv, vltDefaultAddr)
		vlt.Env = append(os.Environ(), fmt.Sprintf("%s=%s", vltAddrEnv, vltDefaultAddr))
	}

	var bStdout, bStderr bytes.Buffer
	vlt.Stdout = &bStdout
	vlt.Stderr = &bStderr

	err := vlt.Run()
	if err != nil {
		// Full command is not printed here.
		t.Fatalf("Failed to exec %q\n\tstderr:\n%s", vltBin, bStderr.String())
	}

	err = json.Unmarshal(bStdout.Bytes(), &token)
	if err != nil {
		t.Fatalf("Failed to unmarshal token: %v", err)
	}
	return
}

// restVault makes HTTP calls to Vault server.
func restVault(t *testing.T, method, path string, body []byte, token string) (int, []byte) {
	t.Helper()

	client := new(http.Client)

	url := vltDefaultAddr + path

	var (
		req *http.Request
		err error
	)
	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatalf("Failed to build HTTP request (url: %s): %v", url, err)
	}

	if token != "" {
		req.Header.Add(vltHeaderToken, token)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to do HTTP request (url: %s): %v", url, err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read HTTP response (url: %s): %v", url, err)
	}

	return resp.StatusCode, respBody
}

// mustUnmarshal doesn't return error. Test will be failed if error occur.
func mustUnmarshal(t *testing.T, data []byte, v interface{}) {
	t.Helper()

	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}
