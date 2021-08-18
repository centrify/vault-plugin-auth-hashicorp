package centrify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/suite"

	"github.com/centrify/platform-go-sdk/testutils"
)

type UsersTestSuite struct {
	testutils.CfyTestSuite
	Backend    *backend
	vaultToken string
	username   string
}

type vaultUserResponse struct {
	Data struct {
		Policies []string `json:"policies"`
	} `json:"data"`
}

var userTests = []struct {
	input string
	want  []string
}{
	{input: "policyA", want: []string{"policya"}},
	{input: "policyA,policyB,policyC", want: []string{"policya", "policyb", "policyc"}},
	{input: "", want: []string(nil)},
}

func (s *UsersTestSuite) SetupSuite() {
	t := s.T()
	s.LoadConfig()

	s.vaultToken = *testutils.VaultRootToken
	s.username = s.Config.PASuser.Username

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

func (s *UsersTestSuite) SetupTest() {
	s.cleanup()
}

func (s *UsersTestSuite) cleanup() {
	t := s.T()
	s.RequiresVault()

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "users/" + s.username,
		Storage:   testStorage,
	})
	if res != nil {
		s.Assert().Empty(res.Auth.Policies)
	}
	if err != nil {
		t.Error(err)
	}

	_ = cliVaultLogin(t, s.vaultToken)
	_ = cliVault(t, s.vaultToken, "delete", "auth/centrify/users/"+s.username)
	_ = cliVault(t, s.vaultToken, "write", "auth/centrify/config", "policies=all_users")
}

func (s *UsersTestSuite) TestIsolatedBackendUserPolicy() {
	t := s.T()
	s.RequiresVault()

	t.Cleanup(s.cleanup)

	for _, test := range userTests {
		s.cleanup()

		res, err := s.Backend.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "users/" + s.username,
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
				"username": s.Config.PASuser.Username,
				"password": s.Config.PASuser.Password,
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

func (s *UsersTestSuite) TestRestAPIPolicy() {
	t := s.T()
	s.RequiresVault()

	t.Cleanup(s.cleanup)

	for _, test := range userTests {
		s.cleanup()

		// write policies
		policiesBody := []byte(fmt.Sprintf(`{"policies":"%s"}`, test.input))
		respCode, _ := restVault(t, "POST", "/v1/auth/centrify/users/"+s.username, policiesBody, s.vaultToken)
		s.Assert().Equal(http.StatusNoContent, respCode)

		// read policies
		_, respBody := restVault(t, "GET", "/v1/auth/centrify/users/"+s.username, nil, s.vaultToken)

		userResponse := &vaultUserResponse{}
		err := json.Unmarshal(respBody, userResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(userResponse.Data.Policies)
		sort.Strings(test.want)
		s.Assert().Equal(test.want, userResponse.Data.Policies)

		// check policies
		loginBody := fmt.Sprintf(
			`{"username":"%s", "password":"%s"}`,
			s.Config.PASuser.Username, s.Config.PASuser.Password,
		)
		_, respBody = restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")

		loginResponse := &authVaultLoginResponse{}
		err = json.Unmarshal(respBody, loginResponse)
		if err != nil {
			t.Error(err)
		}

		expectedPolicies := append(test.want, "all_users", "default")
		sort.Strings(expectedPolicies)
		sort.Strings(loginResponse.Auth.Policies)
		s.Assert().Equal(expectedPolicies, loginResponse.Auth.Policies)
	}
}

func (s *UsersTestSuite) TestCLIPolicy() {
	t := s.T()
	s.RequiresVault()

	t.Cleanup(s.cleanup)

	for _, test := range userTests {
		_ = cliVaultLogin(t, s.vaultToken)

		s.cleanup()

		// write policies
		input := fmt.Sprintf(`policies=%s`, test.input)
		_ = cliVault(t, s.vaultToken, "write", "auth/centrify/users/"+s.username, input)

		// read policies
		out := cliVault(t, s.vaultToken, "read", "-format=json", "auth/centrify/users/"+s.username)

		userResponse := &vaultUserResponse{}
		err := json.Unmarshal(out, userResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(userResponse.Data.Policies)
		sort.Strings(test.want)
		s.Assert().Equal(test.want, userResponse.Data.Policies)

		// check policies
		token := cliVaultLogin(t, "-method=centrify",
			fmt.Sprintf("username=%s", s.Config.PASuser.Username),
			fmt.Sprintf("password=%s", s.Config.PASuser.Password),
		)
		out = cliVault(t, token, "token", "lookup", "-format=json")

		vaultResponse := &vaultUserResponse{}
		err = json.Unmarshal(out, vaultResponse)
		if err != nil {
			t.Error(err)
		}
		expectedPolicies := userResponse.Data.Policies
		sort.Strings(expectedPolicies)
		sort.Strings(test.want)
		s.Assert().Equal(test.want, expectedPolicies)
	}
}

func (s *UsersTestSuite) TestDeletingNonExistingUserPolicies() {
	t := s.T()
	s.RequiresVault()

	ID, _ := uuid.GenerateUUID()
	usernameCLI := ID + "_CLI"
	usernameREST := ID + "_REST"
	usernameBackend := ID + "_backend"

	_ = cliVaultLogin(t, s.vaultToken)
	_ = cliVault(t, s.vaultToken, "delete", "auth/centrify/users/"+usernameCLI)

	respCode, _ := restVault(t, "DELETE", "/v1/auth/centrify/users/"+usernameREST, nil, s.vaultToken)
	s.Assert().Equal(http.StatusNoContent, respCode)

	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "users/" + usernameBackend,
		Storage:   testStorage,
	})
	if res != nil {
		s.Assert().Empty(res.Auth.Policies)
	}
	if err != nil {
		t.Error(err)
	}
}

func (s *UsersTestSuite) TestListUserPolicies() {
	t := s.T()
	s.RequiresVault()

	_ = cliVaultLogin(t, s.vaultToken)
	_ = cliVault(t, s.vaultToken, "write", "auth/centrify/users/list_test_user", "policies=list_policy")

	out := cliVault(t, s.vaultToken, "list", "-format=json", "auth/centrify/users")

	listResponse := []string{}
	err := json.Unmarshal(out, &listResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotEmpty(listResponse)

	// REST
	_, respBody := restVault(t, "LIST", "/v1/auth/centrify/users", nil, s.vaultToken)

	listRESTResponse := &vaultListResponse{}
	err = json.Unmarshal(respBody, listRESTResponse)
	if err != nil {
		t.Error(err)
	}
	s.Assert().NotEmpty(listRESTResponse.Data.Keys)

	// backend
	_, err = s.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "users/" + s.username,
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
		Path:      "users",
		Storage:   testStorage,
	})
	if res != nil {
		s.Assert().NotEmpty(res.Data["keys"].([]string))
	}
	if err != nil {
		t.Error(err)
	}
}

func (s *UsersTestSuite) TestUserBoundary() {
	t := s.T()
	s.RequiresVault()

	var fewPolicy []string
	for i := 0; i <= 10; i++ {
		fewPolicy = append(fewPolicy, fmt.Sprintf("user%d", i))
	}
	sort.Strings(fewPolicy)
	fewPolicyString := strings.Join(fewPolicy, ",")

	var manyPolicy []string
	for i := 0; i <= 300; i++ {
		manyPolicy = append(manyPolicy, fmt.Sprintf("user%d", i))
	}
	sort.Strings(manyPolicy)
	manyPolicyStrig := strings.Join(manyPolicy, ",")

	startTotal := time.Now()

	var (
		username         string
		input            string
		expectedPolicies []string
		start            time.Time
		err              error
	)

	const cycles = 10000
	readDurations := make([]time.Duration, 0, cycles)
	writeDurations := make([]time.Duration, 0, cycles)

	for i := 1; i <= cycles; i++ {
		username = fmt.Sprintf("user%d", i)

		if i <= 1000 {
			input = manyPolicyStrig
			expectedPolicies = manyPolicy
		} else {
			input = fewPolicyString
			expectedPolicies = fewPolicy
		}

		policiesBody := []byte(fmt.Sprintf(`{"policies":"%s"}`, input))

		start = time.Now()
		respCode, _ := restVault(t, "POST", "/v1/auth/centrify/users/"+username, policiesBody, s.vaultToken)
		writeDurations = append(writeDurations, time.Since(start))

		s.Assert().Equal(http.StatusNoContent, respCode)

		start = time.Now()
		respCode, respBody := restVault(t, "GET", "/v1/auth/centrify/users/"+username, nil, s.vaultToken)
		readDurations = append(readDurations, time.Since(start))

		s.Assert().Equal(http.StatusOK, respCode)

		userResponse := &vaultUserResponse{}
		err = json.Unmarshal(respBody, userResponse)
		if err != nil {
			t.Error(err)
		}

		sort.Strings(userResponse.Data.Policies)
		s.Assert().Equal(expectedPolicies, userResponse.Data.Policies)
	}
	durTotal := time.Since(startTotal)

	min, max := findMinAndMax(writeDurations)
	writeTotal := time.Duration(0)
	for _, v := range writeDurations {
		writeTotal += v
	}
	t.Log("[Write] Slowest: ", max)
	t.Log("[Write] Fastest: ", min)
	t.Log("[Write] Average: ", int(writeTotal.Microseconds())/len(writeDurations)/1000, "ms")

	min, max = findMinAndMax(readDurations)
	readTotal := time.Duration(0)
	for _, v := range readDurations {
		readTotal += v
	}
	t.Log("[Read] Slowest: ", max)
	t.Log("[Read] Fastest: ", min)
	t.Log("[Read] Average: ", int(readTotal.Microseconds())/len(readDurations)/1000, "ms")
	t.Log("Total: ", durTotal)

	// login time
	loginBody := fmt.Sprintf(
		`{"username":"%s", "password":"%s"}`,
		s.Config.PASuser.Username, s.Config.PASuser.Password,
	)

	loginStart := time.Now()
	_, respBody := restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")
	loginDuration := time.Since(loginStart)

	loginResponse := &authVaultLoginResponse{}
	err = json.Unmarshal(respBody, loginResponse)
	if err != nil {
		t.Error(err)
	}
	t.Log("Login duration: ", loginDuration)
}

func (s *UsersTestSuite) TestNoUserPolicyAssigned() {
	t := s.T()
	s.RequiresVault()

	t.Cleanup(s.cleanup)

	expectedPolicies := []string{"all_users", "default"}
	sort.Strings(expectedPolicies)

	// isolated backend
	res, err := s.Backend.HandleRequest(ctx, &logical.Request{
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
		sort.Strings(res.Auth.Policies)
		s.Assert().Equal([]string{"all_users"}, res.Auth.Policies)
	}

	// cli
	token := cliVaultLogin(t, "-method=centrify",
		fmt.Sprintf("username=%s", s.Config.PolicyChangeUser.Username),
		fmt.Sprintf("password=%s", s.Config.PolicyChangeUser.Password),
	)
	out := cliVault(t, token, "token", "lookup", "-format=json")

	vaultResponse := &vaultUserResponse{}
	err = json.Unmarshal(out, vaultResponse)
	if err != nil {
		t.Error(err)
	}
	sort.Strings(vaultResponse.Data.Policies)
	s.Assert().Equal(expectedPolicies, vaultResponse.Data.Policies)

	// rest
	loginBody := fmt.Sprintf(
		`{"username":"%s", "password":"%s"}`,
		s.Config.PolicyChangeUser.Username, s.Config.PolicyChangeUser.Password,
	)
	_, respBody := restVault(t, "POST", "/v1/auth/centrify/login", []byte(loginBody), "")

	loginResponse := &authVaultLoginResponse{}
	err = json.Unmarshal(respBody, loginResponse)
	if err != nil {
		t.Error(err)
	}
	sort.Strings(loginResponse.Auth.Policies)
	s.Assert().Equal(expectedPolicies, loginResponse.Auth.Policies)
}

func findMinAndMax(a []time.Duration) (min time.Duration, max time.Duration) {
	min = a[0]
	max = a[0]
	for _, value := range a {
		if value < min {
			min = value
		}
		if value > max {
			max = value
		}
	}
	return min, max
}

func TestUsersTestSuite(t *testing.T) {
	suite.Run(t, new(UsersTestSuite))
}
