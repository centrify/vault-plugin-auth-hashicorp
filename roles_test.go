package centrify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/centrify/platform-go-sdk/testutils"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/suite"
)

const (
	testRoleName = "Role1"
)

type RolesTestSuite struct {
	testutils.CfyTestSuite
	Backend    *backend
	vaultToken string
	rolename   string
}

type vaultRoleResponse struct {
	Data struct {
		Policies []string `json:"policies"`
	} `json:"data"`
	LeaseDuration int64       `json:"lease_duration"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	RequestID     string      `json:"request_id"`
	Warnings      interface{} `json:"warnings"`
}

type vaultListResponse struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Keys []string `json:"keys"`
	} `json:"data"`
	WrapInfo interface{} `json:"wrap_info"`
	Warnings interface{} `json:"warnings"`
	Auth     interface{} `json:"auth"`
}

var roleTests = []struct {
	input string
	want  []string
}{
	{input: "policyA", want: []string{"policya"}},
	{input: "policyA,policyB,policyC", want: []string{"policya", "policyb", "policyc"}},
	// 2 policies
	{input: "policyZ1,policyZ2", want: []string{"policyz1", "policyz2"}},
	// 5 policies
	{input: "policyZ1,policyZ2,policyZ3,policyZ4,policyZ5", want: []string{"policyz1", "policyz2", "policyz3",
		"policyz4", "policyz5"}},
	// 20 policies
	{input: "policyZ1,policyZ2,policyZ3,policyZ4,policyZ5,policyZ6,policyZ7,policyZ8,policyZ9,policyZ10,policyZ11," +
		"policyZ12,policyZ13,policyZ14,policyZ15,policyZ16,policyZ17,policyZ18,policyZ19,policyZ20",
		want: []string{"policyz1", "policyz2", "policyz3", "policyz4", "policyz5", "policyz6", "policyz7", "policyz8",
			"policyz9", "policyz10", "policyz11", "policyz12", "policyz13", "policyz14", "policyz15", "policyz16",
			"policyz17", "policyz18", "policyz19", "policyz20"}},
}

func (s *RolesTestSuite) SetupSuite() {
	t := s.T()
	s.LoadConfig()

	s.vaultToken = *testutils.VaultRootToken
	s.rolename = testRoleName
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

func (s *RolesTestSuite) SetupTest() {
	s.cleanup()
}

func (s *RolesTestSuite) TearDownTest() {
	s.cleanup()
}

func (s *RolesTestSuite) cleanup() {
	t := s.T()
	s.RequiresVault()
	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + s.rolename,
		Storage:   testStorage,
	})
	if res != nil {
		s.Assert().Len(res.Auth.Policies, 0)
	}
	if err != nil {
		t.Error(err)
	}

	_ = cliVaultLogin(t, s.vaultToken)
	_ = cliVault(t, s.vaultToken, "delete", "auth/centrify/roles/"+s.rolename)
	_ = cliVault(t, s.vaultToken, "write", "auth/centrify/config", "policies=all_users")
}

func (s *RolesTestSuite) TestIsolatedBackendRolePolicy() {
	t := s.T()

	for _, test := range roleTests {
		res, err := s.Backend.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/" + s.rolename,
			Storage:   testStorage,
			Data: map[string]interface{}{
				"policies": "",
			},
		})
		if res != nil {
			t.Logf("res: %+v\n", res)
			s.Assert().Empty(res.Auth.Policies)
		}
		if err != nil {
			t.Error(err)
		}

		res, err = s.Backend.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/" + s.rolename,
			Storage:   testStorage,
			Data: map[string]interface{}{
				"policies": test.input,
			},
		})
		if res != nil {
			t.Logf("res: %+v\n", res)
			sort.Strings(res.Auth.Policies)
			sort.Strings(test.want)
			s.Assert().Equal(test.want, res.Auth.Policies)
		}
		if err != nil {
			t.Error(err)
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
			t.Error(err)
		}
		if res != nil {
			wantedPolicies := append(test.want, "all_users")
			sort.Strings(wantedPolicies)
			sort.Strings(res.Auth.Policies)
			s.Assert().Equal(wantedPolicies, res.Auth.Policies)
		}
	}
}

func (s *RolesTestSuite) TestRestAPIPolicy() {
	t := s.T()
	s.RequiresVault()

	noPoliciesBody := []byte(`{"policies": ""}`)

	var (
		respCode     int
		respBody     []byte
		policiesBody []byte
		err          error
	)
	for _, test := range roleTests {
		respCode, _ = restVault(t, "POST", "/v1/auth/centrify/roles/"+s.rolename, noPoliciesBody, s.vaultToken)
		s.Assert().Equal(http.StatusNoContent, respCode)

		// write policies
		policiesBody = []byte(fmt.Sprintf(`{"policies": "%s"}`, test.input))
		respCode, _ = restVault(t, "POST", "/v1/auth/centrify/roles/"+s.rolename, policiesBody, s.vaultToken)
		s.Assert().Equal(http.StatusNoContent, respCode)

		// read policies
		_, respBody = restVault(t, "GET", "/v1/auth/centrify/roles/"+s.rolename, nil, s.vaultToken)
		roleResponse := &vaultRoleResponse{}
		err = json.Unmarshal(respBody, roleResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(test.want)
		sort.Strings(roleResponse.Data.Policies)
		s.Assert().Equal(test.want, roleResponse.Data.Policies)

		// check policies
		loginBody := fmt.Sprintf(
			`{"username":"%s", "password":"%s"}`,
			s.Config.PolicyChangeUser.Username, s.Config.PolicyChangeUser.Password,
		)
		_, respBody = restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")

		loginResponse := &authVaultLoginResponse{}
		err = json.Unmarshal(respBody, loginResponse)
		if err != nil {
			t.Error(err)
		}

		test.want = append(test.want, "all_users", "default")
		sort.Strings(loginResponse.Auth.Policies)
		sort.Strings(test.want)
		s.Assert().Equal(test.want, loginResponse.Auth.Policies)
	}
}

func (s *RolesTestSuite) TestCLIPolicy() {
	t := s.T()
	s.RequiresVault()

	for _, test := range roleTests {
		_ = cliVaultLogin(t, s.vaultToken)

		// clean up
		_ = cliVault(t, s.vaultToken, "write", "auth/centrify/roles/"+s.rolename, `policies=""`)

		// write policies
		input := fmt.Sprintf(`policies=%s`, test.input)
		_ = cliVault(t, s.vaultToken, "write", "auth/centrify/roles/"+s.rolename, input)

		// read policies
		out := cliVault(t, s.vaultToken, "read", "-format=json", "auth/centrify/roles/"+s.rolename)
		roleResponse := &vaultRoleResponse{}
		err := json.Unmarshal(out, roleResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(test.want)
		s.Assert().Equal(test.want, roleResponse.Data.Policies)

		// check policies
		token := cliVaultLogin(t, "-method=centrify",
			fmt.Sprintf("username=%s", s.Config.PolicyChangeUser.Username),
			fmt.Sprintf("password=%s", s.Config.PolicyChangeUser.Password),
		)
		out = cliVault(t, token, "token", "lookup", "-format=json")

		vaultResponse := &vaultRoleResponse{}
		err = json.Unmarshal(out, vaultResponse)
		if err != nil {
			t.Error(err)
		}

		expectedPolicies := append(test.want, "all_users", "default")
		sort.Strings(expectedPolicies)
		sort.Strings(vaultResponse.Data.Policies)
		s.Assert().Equal(expectedPolicies, vaultResponse.Data.Policies)
	}
}

func (s *RolesTestSuite) TestDeletingNonExistingRoles() {
	t := s.T()

	s.RequiresVault()

	ID, _ := uuid.GenerateUUID()
	rolenameCLI := ID + "_CLI"
	rolenameREST := ID + "_REST"
	rolenameBackend := ID + "_backend"

	// cli
	_ = cliVaultLogin(t, s.vaultToken)
	_ = cliVault(t, s.vaultToken, "delete", "auth/centrify/roles/"+rolenameCLI)

	// REST
	respCode, _ := restVault(t, "DELETE", "/v1/auth/centrify/roles/"+rolenameREST, nil, s.vaultToken)
	s.Assert().Equal(http.StatusNoContent, respCode)

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + rolenameBackend,
		Storage:   testStorage,
	})
	if res != nil {
		s.Assert().Empty(res.Auth.Policies)
	}
	if err != nil {
		t.Error(err)
	}
}

func (s *RolesTestSuite) TestListRoles() {
	t := s.T()

	s.RequiresVault()

	// write some roles to have at least one in list
	_ = cliVaultLogin(t, s.vaultToken)

	// write policies
	_ = cliVault(t, s.vaultToken, "write", "auth/centrify/roles/list_test_role", "policies=list_policy")

	// CLI
	out := cliVault(t, s.vaultToken, "list", "-format=json", "auth/centrify/roles/")
	listResponse := []string{}
	err := json.Unmarshal(out, &listResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotEmpty(listResponse)

	// REST
	_, respBody := restVault(t, "LIST", "/v1/auth/centrify/roles", nil, s.vaultToken)

	listRESTResponse := &vaultListResponse{}
	err = json.Unmarshal(respBody, listRESTResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotEmpty(listRESTResponse.Data.Keys)

	// backend

	_, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + s.rolename,
		Storage:   testStorage,
		Data: map[string]interface{}{
			"policies": "not_important",
		},
	})
	if err != nil {
		t.Error(err)
	}
	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   testStorage,
	})
	if res != nil {
		s.Assert().NotEmpty(res.Data["keys"].([]string))
	}
	if err != nil {
		t.Error(err)
	}
}

func TestRolesTestSuite(t *testing.T) {
	suite.Run(t, new(RolesTestSuite))
}
