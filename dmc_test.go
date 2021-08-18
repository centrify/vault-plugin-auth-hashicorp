//nolint:funlen
package centrify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/centrify/platform-go-sdk/testutils"
)

type DMCTestSuite struct {
	testutils.CfyTestSuite
	Backend    *backend
	vaultToken string
}

func (s *DMCTestSuite) SetupSuite() {
	s.LoadConfig()

	// normalize URL
	if !strings.HasPrefix(s.Config.TenantURL, "https://") {
		s.Config.TenantURL = "https://" + s.Config.TenantURL
	}

	u, err := url.Parse(s.Config.TenantURL)
	if err != nil {
		s.T().Skip("Can't parse tenant URL from config")
	}

	s.Config.TenantURL = u.Host
	s.vaultToken = *testutils.VaultRootToken
}

func (s *DMCTestSuite) TestUseMachineCredentialREST() {
	t := s.T()
	s.RequiresActiveTenant()
	s.RequiresVault()

	var err error

	respCode, respBody := restVault(
		t, "POST", "/v1/auth/centrify/config",
		[]byte(`{"use_machine_credential": true}`),
		s.vaultToken,
	)
	if respCode != http.StatusNoContent {
		t.Log("response:", string(respBody))
	}
	s.Assert().Equal(http.StatusNoContent, respCode)

	// login must succeed
	loginBody := fmt.Sprintf(
		`{"username":"%s", "password": "%s"}`,
		s.Config.PASuser.Username,
		s.Config.PASuser.Password,
	)
	respCode, respBody = restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")
	s.Assert().Equal(http.StatusOK, respCode)

	loginResponse := &authVaultLoginResponse{}
	err = json.Unmarshal(respBody, loginResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotNil(loginResponse.Auth.Policies)

	// check config
	_, respBody = restVault(t, "GET", "/v1/auth/centrify/config", nil, s.vaultToken)

	configResponse := &authVaultConfigResponse{}
	err = json.Unmarshal(respBody, configResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().Equal("", configResponse.Data.ClientSecret)
	s.Assert().NotEmpty(configResponse.Data.ClientID)
	s.Assert().Equal(defaultAppID, configResponse.Data.AppID)
	s.Assert().Equal(defaultScope, configResponse.Data.Scope)
	s.Assert().Equal(true, configResponse.Data.UseMachineCredential)
	s.Assert().NotEqual("", configResponse.Data.ServiceURL)

	// write configuration back
	newConfig := authPluginConfig{
		AppID:                s.Config.AppID,
		ClientID:             s.Config.ClientID,
		Scope:                s.Config.Scope,
		ClientSecret:         s.Config.ClientSecret,
		ServiceURL:           s.Config.TenantURL,
		UseMachineCredential: false,
		Policies:             []string{"all_users"},
	}
	t.Log(s.Config.TenantURL)
	newConfigString, err := json.Marshal(newConfig)
	if err != nil {
		t.Error(err)
	}

	respCode, respBody = restVault(t, "POST", "/v1/auth/centrify/config", newConfigString, s.vaultToken)
	if respCode != http.StatusNoContent {
		t.Log(string(respBody))
	}
	s.Assert().Equal(http.StatusNoContent, respCode)

	// try to login
	loginBody = fmt.Sprintf(
		`{"username":"%s", "password": "%s"}`,
		s.Config.PASuser.Username,
		s.Config.PASuser.Password,
	)
	respCode, respBody = restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")
	s.Assert().Equal(http.StatusOK, respCode)

	loginResponse = &authVaultLoginResponse{}
	err = json.Unmarshal(respBody, loginResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotNil(loginResponse.Auth.Policies)
}
func (s *DMCTestSuite) TestUseMachineCredentialCLI() {
	t := s.T()
	s.RequiresActiveTenant()
	s.RequiresVault()

	_ = cliVaultLogin(t, s.vaultToken)
	_ = cliVault(t, s.vaultToken, "write", "auth/centrify/config", "use_machine_credential=true")

	// Check if login works.
	_ = cliVaultLogin(t, "-method=centrify",
		"username="+s.Config.PASuser.Username,
		"password="+s.Config.PASuser.Password,
	)

	_ = cliVaultLogin(t, s.vaultToken)
	out := cliVault(t, s.vaultToken, "read", "-format=json", "auth/centrify/config")

	configResponse := &authVaultConfigResponse{}
	err := json.Unmarshal(out, configResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().Equal("", configResponse.Data.ClientSecret)
	s.Assert().NotEmpty(configResponse.Data.ClientID)
	s.Assert().Equal(defaultAppID, configResponse.Data.AppID)
	s.Assert().Equal(defaultScope, configResponse.Data.Scope)
	s.Assert().Equal(true, configResponse.Data.UseMachineCredential)
	s.Assert().NotEqual("", configResponse.Data.ServiceURL)

	_ = cliVault(t, s.vaultToken, "write", "auth/centrify/config",
		"app_id="+s.Config.AppID,
		"client_id="+s.Config.ClientID,
		"client_secret="+s.Config.ClientSecret,
		"scope="+s.Config.AppID,
		"service_url="+s.Config.TenantURL,
		"use_machine_credential=false",
		"policies=all_users",
	)

	// Check if login works.
	_ = cliVaultLogin(t, "-method=centrify",
		"username="+s.Config.PASuser.Username,
		"password="+s.Config.PASuser.Password,
	)
}

func (s *DMCTestSuite) TestUseMachineCredentialCLIFail() {
	t := s.T()
	s.RequiresVault()
	s.RequiresCClientNotRunning()
	var stderr bytes.Buffer

	cmd := exec.Command("vault", "write", "auth/centrify/config", "use_machine_credential=true")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	s.Assert().Error(err)
	if err == nil {
		t.Log(string(out))
		t.Log(stderr.String())
	}

}
func (s *DMCTestSuite) TestUseMachineCredentialRESTFail() {
	t := s.T()
	s.RequiresVault()
	s.RequiresCClientNotRunning()

	newConfig := authPluginConfig{
		UseMachineCredential: true,
	}
	newConfigBytes, err := json.Marshal(newConfig)
	if err != nil {
		t.Error(err)
	}

	respCode, respBody := restVault(
		t, "POST", "/v1/auth/centrify/config", newConfigBytes, s.vaultToken,
	)
	failHTTPCodes := []int{http.StatusBadRequest, http.StatusInternalServerError}
	for _, httpCode := range failHTTPCodes {
		if httpCode == respCode {
			t.Log(string(respBody))
			break
		}
	}
	s.Assert().Contains(failHTTPCodes, respCode)
}

func TestDMCTestSuite(t *testing.T) {
	suite.Run(t, new(DMCTestSuite))
}
