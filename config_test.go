package centrify

import (
	"testing"

	"github.com/centrify/platform-go-sdk/testutils"
	"github.com/stretchr/testify/suite"
)

type authPluginConfig struct {
	AppID                string   `json:"app_id,omitempty"`
	ClientID             string   `json:"client_id,omitempty"`
	ClientSecret         string   `json:"client_secret,omitempty"`
	Policies             []string `json:"policies,omitempty"`
	TokenPolicies        []string `json:"token_policies,omitempty"`
	RolesAsPolicies      bool     `json:"roles_as_policies"`
	Scope                string   `json:"scope,omitempty"`
	ServiceURL           string   `json:"service_url,omitempty"`
	PolicyPrefix         string   `json:"policy_prefix,omitempty"`
	UseMachineCredential bool     `json:"use_machine_credential"`
	HTTPLogs             bool     `json:"http_logs"`
}

type authVaultConfigResponse struct {
	Auth          interface{}      `json:"auth"`
	Data          authPluginConfig `json:"data"`
	LeaseDuration int64            `json:"lease_duration"`
	LeaseID       string           `json:"lease_id"`
	Renewable     bool             `json:"renewable"`
	RequestID     string           `json:"request_id"`
	Warnings      interface{}      `json:"warnings"`
	WrapInfo      interface{}      `json:"wrap_info"`
}

type ConfigTestSuite struct {
	testutils.CfyTestSuite
	vaultToken string
}

func (s *ConfigTestSuite) SetupSuite() {
	s.LoadConfig()
	s.vaultToken = *testutils.VaultRootToken
}

func (s *ConfigTestSuite) TestRestAPIConfigHiddenClientSecret() {
	t := s.T()
	s.RequiresVault()

	_, resp := restVault(t, "GET", "/v1/auth/centrify/config", nil, s.vaultToken)

	configResponse := &authVaultConfigResponse{}
	mustUnmarshal(t, resp, configResponse)
	s.Assert().Equal("", configResponse.Data.ClientSecret)
}

func (s *ConfigTestSuite) TestCLIConfigHiddenClientSecret() {
	t := s.T()
	s.RequiresVault()

	_ = cliVaultLogin(t, s.vaultToken)
	out := cliVault(t, s.vaultToken, "read", "-format=json", "auth/centrify/config")

	configResponse := &authVaultConfigResponse{}
	mustUnmarshal(t, out, configResponse)
	s.Assert().Equal("", configResponse.Data.ClientSecret)
}

func (s *ConfigTestSuite) TestHTTPLogsConfig() {
	t := s.T()
	s.RequiresVault()

	token := s.vaultToken

	cliVault(t, token, "write", "auth/centrify/config", "http_logs=true")

	out := cliVault(t, token, "read", "-format=json", "auth/centrify/config")

	configResponse := &authVaultConfigResponse{}
	mustUnmarshal(t, out, configResponse)
	s.Assert().Equal(true, configResponse.Data.HTTPLogs)

	cliVault(t, token, "write", "auth/centrify/config", "http_logs=false")

	out = cliVault(t, token, "read", "-format=json", "auth/centrify/config")

	configResponse = &authVaultConfigResponse{}
	mustUnmarshal(t, out, configResponse)
	s.Assert().Equal(false, configResponse.Data.HTTPLogs)
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}
