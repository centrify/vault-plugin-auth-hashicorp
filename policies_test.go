package centrify

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/suite"

	"github.com/centrify/platform-go-sdk/testutils"
)

var (
	defaultLeaseTTLVal = time.Second * 100
	maxLeaseTTLVal     = time.Second * 20
	ctx                = context.Background()
	testStorage        = &logical.InmemStorage{}
)

type PolicyTestSuite struct {
	testutils.CfyTestSuite
	Backend    *backend
	vaultToken string
}

type authVaultLoginResponse struct {
	Auth struct {
		Accessor      string `json:"accessor"`
		ClientToken   string `json:"client_token"`
		EntityID      string `json:"entity_id"`
		LeaseDuration int64  `json:"lease_duration"`
		Metadata      struct {
			Username string `json:"username"`
		} `json:"metadata"`
		Orphan        bool     `json:"orphan"`
		Policies      []string `json:"policies"`
		Renewable     bool     `json:"renewable"`
		TokenPolicies []string `json:"token_policies"`
		TokenType     string   `json:"token_type"`
	} `json:"auth"`
	Data          authPluginConfig `json:"data"`
	LeaseDuration int64            `json:"lease_duration"`
	LeaseID       string           `json:"lease_id"`
	Renewable     bool             `json:"renewable"`
	RequestID     string           `json:"request_id"`
	Warnings      interface{}      `json:"warnings"`
	WrapInfo      interface{}      `json:"wrap_info"`
}

var tests = []struct {
	input []string
	want  []string
}{
	{input: []string{"all_users"}, want: []string{"all_users"}},
	{input: []string{"PAS_users", "engineering"}, want: []string{"engineering", "pas_users"}},
	{input: []string{"all_users", "engineering"}, want: []string{"all_users", "engineering"}},
}

func (s *PolicyTestSuite) SetupSuite() {
	t := s.T()
	s.LoadConfig()

	s.vaultToken = *testutils.VaultRootToken

	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
	}

	testBackend := Backend()
	s.Backend = testBackend

	if err := testBackend.Setup(ctx, conf); err != nil {
		t.Error(err)
	}
	res, err := testBackend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_url":   s.Config.TenantURL,
			"client_id":     s.Config.ClientID,
			"client_secret": s.Config.ClientSecret,
			"app_id":        s.Config.AppID,
			"policies":      "all_users",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Error(err)
	}
}

func (s *PolicyTestSuite) TestIsolatedBackendOnePolicy() {
	t := s.T()

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"policies": "engineering",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PASuser.Username,
			"password": s.Config.PASuser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		sort.Strings(res.Auth.Policies)
		s.Assert().Equal([]string{"engineering"}, res.Auth.Policies)
	}
}

func (s *PolicyTestSuite) TestIsolatedBackendManyPolicy() {
	t := s.T()

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"policies": "engineering, PAS_user",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PASuser.Username,
			"password": s.Config.PASuser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		sort.Strings(res.Auth.Policies)
		s.Assert().Equal([]string{"engineering", "pas_user"}, res.Auth.Policies)
	}
}

func (s *PolicyTestSuite) TestRestAPIPolicySuite() { //nolint:dupl
	t := s.T()
	s.RequiresVault()

	for _, test := range tests {
		input, _ := json.Marshal(struct {
			Policies []string `json:"policies"`
		}{
			Policies: test.input,
		})
		_, _ = restVault(t, "POST", "/v1/auth/centrify/config", input, s.vaultToken)
		_, resp := restVault(t, "GET", "/v1/auth/centrify/config", nil, s.vaultToken)

		configResponse := &authVaultConfigResponse{}
		err := json.Unmarshal(resp, configResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(configResponse.Data.Policies)
		s.Assert().Equal(test.want, configResponse.Data.Policies)
	}

	loginBody := fmt.Sprintf(
		`{"username":"%s", "password":"%s"}`,
		s.Config.PASuser.Username, s.Config.PASuser.Password,
	)
	_, resp := restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")

	loginResponse := &authVaultLoginResponse{}
	err := json.Unmarshal(resp, loginResponse)
	if err != nil {
		t.Error(err)
	}

	sort.Strings(loginResponse.Auth.Policies)
	s.Assert().Equal([]string{"all_users", "default", "engineering"}, loginResponse.Auth.Policies)
}

func (s *PolicyTestSuite) TestCLIPolicySuite() {
	t := s.T()
	s.RequiresVault()

	_ = cliVaultLogin(t, s.vaultToken)

	for _, test := range tests {
		input := fmt.Sprintf("policies=%s", strings.Join(test.input, ", "))

		_ = cliVault(t, s.vaultToken, "write", "auth/centrify/config", input)
		out := cliVault(t, s.vaultToken, "read", "-format=json", "auth/centrify/config")

		configResponse := &authVaultConfigResponse{}
		err := json.Unmarshal(out, configResponse)
		if err != nil {
			t.Error(err)
		}

		s.Assert().Equal(test.want, configResponse.Data.Policies)
	}

	token := cliVaultLogin(t, "-method=centrify",
		fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password),
	)
	out := cliVault(t, token, "token", "lookup", "-format=json")

	configResponse := &authVaultConfigResponse{}
	err := json.Unmarshal(out, configResponse)
	if err != nil {
		t.Error(err)
	}

	sort.Strings(configResponse.Data.Policies)
	s.Assert().Equal([]string{"all_users", "default", "engineering"}, configResponse.Data.Policies)
}

func (s *PolicyTestSuite) TearDownTest() {
	t := s.T()
	s.RequiresVault()

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"token_policies":    "engineering",
			"roles_as_policies": "false",
			"policy_prefix":     "",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Error(err)
	}

	_ = cliVaultLogin(t, s.vaultToken)
	_ = cliVault(t, s.vaultToken, "write", "auth/centrify/config", "policies=all_users")
}

func (s *PolicyTestSuite) TestRolesAsPolicy() {
	t := s.T()

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"token_policies":    "engineering",
			"roles_as_policies": "true",
			"policy_prefix":     "",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PolicyChangeUser.Username,
			"password": s.Config.PolicyChangeUser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		s.Assert().Contains(res.Auth.Policies, "qa")
		s.Assert().Contains(res.Auth.Policies, "dev")
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"roles_as_policies": "false",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PolicyChangeUser.Username,
			"password": s.Config.PolicyChangeUser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		s.Assert().Equal([]string{"engineering"}, res.Auth.Policies)
	}
}
func (s *PolicyTestSuite) TestPolicyPrefix() {
	t := s.T()

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"policies":          "engineering",
			"roles_as_policies": "true",
			"policy_prefix":     "pas_",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PolicyChangeUser.Username,
			"password": s.Config.PolicyChangeUser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		s.Assert().Contains(res.Auth.Policies, "pas_qa")
		s.Assert().Contains(res.Auth.Policies, "pas_dev")
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"policies":          "engineering",
			"roles_as_policies": "true",
			"policy_prefix":     "",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PolicyChangeUser.Username,
			"password": s.Config.PolicyChangeUser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		s.Assert().Contains(res.Auth.Policies, "qa")
		s.Assert().Contains(res.Auth.Policies, "dev")
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"roles_as_policies": "false",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PolicyChangeUser.Username,
			"password": s.Config.PolicyChangeUser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		s.Assert().Equal([]string{"engineering"}, res.Auth.Policies)
	}
}

func (s *PolicyTestSuite) TestIsolatedBackendManyTokenPolicy() {
	t := s.T()

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"token_policies": "token_policies_policy",
		},
	})
	if res != nil {
		t.Logf("res: %+v\n", res)
	}
	if err != nil {
		t.Fatal(err)
	}

	res, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"username": s.Config.PASuser.Username,
			"password": s.Config.PASuser.Password,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		sort.Strings(res.Auth.Policies)
		s.Assert().Equal([]string{"token_policies_policy"}, res.Auth.TokenPolicies)
		s.Assert().Equal([]string{"token_policies_policy"}, res.Auth.Policies)
	}
}

func (s *PolicyTestSuite) TestRestAPITokenPolicySuite() { //nolint:dupl
	t := s.T()
	s.RequiresVault()

	for _, test := range tests {
		input, _ := json.Marshal(struct {
			TokenPolicies []string `json:"token_policies"`
		}{
			TokenPolicies: test.input,
		})
		_, _ = restVault(t, "POST", "/v1/auth/centrify/config", input, s.vaultToken)
		_, resp := restVault(t, "GET", "/v1/auth/centrify/config", nil, s.vaultToken)

		configResponse := &authVaultConfigResponse{}
		err := json.Unmarshal(resp, configResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(configResponse.Data.TokenPolicies)
		// s.Assert().Equal(test.want, configResponse.Data.Policies)
		s.Assert().Equal(test.want, configResponse.Data.TokenPolicies)
	}

	loginBody := fmt.Sprintf(
		`{"username":"%s", "password":"%s"}`,
		s.Config.PASuser.Username, s.Config.PASuser.Password,
	)
	_, resp := restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")

	loginResponse := &authVaultLoginResponse{}
	err := json.Unmarshal(resp, loginResponse)
	if err != nil {
		t.Error(err)
	}

	sort.Strings(loginResponse.Auth.Policies)
	s.Assert().Equal([]string{"all_users", "default", "engineering"}, loginResponse.Auth.Policies)
}

func (s *PolicyTestSuite) TestCLITokenPolicySuite() {
	t := s.T()
	s.RequiresVault()

	_ = cliVaultLogin(t, s.vaultToken)

	for _, test := range tests {
		input := fmt.Sprintf("token_policies=%s", strings.Join(test.input, ", "))

		_ = cliVault(t, s.vaultToken, "write", "auth/centrify/config", input)
		out := cliVault(t, s.vaultToken, "read", "-format=json", "auth/centrify/config")

		configResponse := &authVaultConfigResponse{}
		err := json.Unmarshal(out, configResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(configResponse.Data.TokenPolicies)
		s.Assert().Equal(test.want, configResponse.Data.TokenPolicies)
	}

	token := cliVaultLogin(t, "-method=centrify",
		fmt.Sprintf("username=%s", s.Config.PASuser.Username),
		fmt.Sprintf("password=%s", s.Config.PASuser.Password),
	)
	out := cliVault(t, token, "token", "lookup", "-format=json")

	configResponse := &authVaultConfigResponse{}
	err := json.Unmarshal(out, configResponse)
	if err != nil {
		t.Error(err)
	}

	sort.Strings(configResponse.Data.Policies)
	s.Assert().Equal([]string{"all_users", "default", "engineering"}, configResponse.Data.Policies)
}

func TestPolicyTestSuite(t *testing.T) {
	suite.Run(t, new(PolicyTestSuite))
}
