package centrify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/centrify/platform-go-sdk/testutils"
	"github.com/centrify/platform-go-sdk/utils"
	"github.com/centrify/platform-go-sdk/vault"
)

const (
	vaultURL   = "http://localhost:8200"
	testsScope = "testsdk"
)

type DMCAppTestSuite struct {
	testutils.CfyTestSuite
	Backend    *backend
	vaultToken string
}

func (s *DMCAppTestSuite) SetupSuite() {
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

func (s *DMCAppTestSuite) TestLoginFromAppREST() {
	t := s.T()
	s.RequiresActiveTenant()
	s.RequiresVault()
	ok, err := utils.VerifyCClientVersionReq("21.6")
	s.Assert().NoError(err, "Problem with getting cagent version info.")
	if !ok {
		t.Skip("CClient version >= 21.6 is required")
	}

	respCode, respBody := restVault(
		t, "POST", "/v1/auth/centrify/config",
		[]byte(`{"use_machine_credential": true}`),
		s.vaultToken,
	)
	if respCode != http.StatusNoContent {
		t.Log("response:", string(respBody))
	}
	s.Assert().Equal(http.StatusNoContent, respCode)

	token, err := vault.GetHashiVaultToken(testsScope, vaultURL)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotEmpty(token)

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
}

func TestDMCAppTestSuite(t *testing.T) {
	suite.Run(t, new(DMCAppTestSuite))
}
