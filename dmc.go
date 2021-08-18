package centrify

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/centrify/cloud-golang-sdk/restapi"
	"github.com/centrify/platform-go-sdk/dmc"
	"github.com/centrify/platform-go-sdk/utils"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	centrifyVaultScope = "__centrify_vault"

	minCClientVersion = "21.5"

	defaultAppIDForDMC = "vault_user"
	defaultAppID       = "vault_io_integration"
	defaultScope       = "vault_io_integration"
)

func (b *backend) getCurrentMachineInfo(token, serviceURL string, httpFactory func() *http.Client) (string, error) {
	b.Logger().Debug("getting information about Centrify Client", "serviceURL", serviceURL)

	restClient, err := restapi.GetNewRestClient(serviceURL, httpFactory)
	if err != nil {
		return "", err
	}

	restClient.Headers["Authorization"] = "Bearer " + token
	restClient.SourceHeader = sourceHeader

	b.Logger().Debug("Verify service account of current machine")
	whoami, err := restClient.CallGenericMapAPI("/security/whoami", nil)
	if err != nil {
		return "", err
	}
	name := whoami.Result["User"].(string) //nolint:forcetypeassert
	b.Logger().Debug("Received Client name from PAS", "name", name)
	return name, nil
}

// checkMachCred checks if the plugin can use machine credential
// returns nil/non-nil error on whether the machine credential is obtained
// Other values returned:
//  - serviceURL: service URL
//  - identity:  identity of the machine
//  - token:	 access token
func (b *backend) checkMachCred(httpFactory func() *http.Client) (string, string, string, error) {
	// check if Centrify Client is installed and meets the version requirement
	verOK, err := utils.VerifyCClientVersionReq(minCClientVersion)
	if err != nil {
		b.Logger().Error("Error in checking Centrify Client version", "error", err.Error())
		return "", "", "", err
	}
	if !verOK {
		b.Logger().Error("Centrify Client version requirement not met.", "expects", minCClientVersion)
		return "", "", "", fmt.Errorf("requires Centrify Client version %s or higher", minCClientVersion)
	}

	b.Logger().Debug("Ready to get enrollment information")
	tenantURL, clientID, err := dmc.GetEnrollmentInfo()
	if err != nil {
		b.Logger().Error("Cannot get information about client enrollment", "error", err.Error())
		return "", "", "", err
	}

	tenantURL = "https://" + tenantURL
	b.Logger().Debug("Received information from Centrify Client", "tenantURL", tenantURL, "client ID", clientID)
	token, err := dmc.GetDMCToken(centrifyVaultScope)
	if err != nil {
		b.Logger().Error("GetDMCToken", "Error in getting token", err.Error())
		return "", "", "", err
	}

	b.Logger().Debug("DMC token received")
	// try to get identity from PAS
	nameFromPAS, err := b.getCurrentMachineInfo(token, tenantURL, httpFactory)
	if err != nil {
		b.Logger().Error("GetDMCToken", "Error in getting machine info from PAS", err.Error())
		return "", "", "", err
	}

	// check if name match
	if !strings.EqualFold(nameFromPAS, clientID) {
		b.Logger().Error("GetDMCToken", "name from token", clientID, "name from PAS", nameFromPAS)
		return "", "", "", errors.New("unexpected machine credential token received")
	}

	return tenantURL, clientID, token, nil
}

// handleAuthParameters checks if authentication related parameters are handled.
//
// 1. If use_machine_credential is not specified, existing value is used (default: false).
// 2. If use_machine_credential is true, ServiceURI, ClientID and ClientSecret MUST NOT be specified.
// 3. If use_machine_credential is false, ServiceURI, ClientID and ClientSecret MUST be specified.
// 4. AppID and Scope are required regardless of use_machine_credential value. They represent the AppID
//		and Scope used by interactive users. The default AppID is "vault_user" and default Scope is "vault_io_integration".
func (b *backend) handleAuthParameters(config *config, req *logical.Request, data *framework.FieldData) (changed bool, errMsg string) {
	vUseMachCred, hasUseMachCred := data.GetOk(cfgUseMachCred)
	vServiceURL, hasServiceURL := data.GetOk(cfgServiceURL)
	vAppID, hasAppID := data.GetOk(cfgAppID)
	vScope, hasScope := data.GetOk(cfgScope)
	vClientID, hasClientID := data.GetOk(cfgClientID)
	vClientSecret, hasClientSecret := data.GetOk(cfgClientSecret)

	changed = hasUseMachCred || hasServiceURL || hasAppID || hasScope || hasClientID || hasClientSecret
	if !changed {
		return
	}

	if hasUseMachCred {
		config.UseMachineCred = vUseMachCred.(bool) //nolint:forcetypeassert
	}

	if config.UseMachineCred {
		// setup list of parameters that should not be specified
		unsupported := []string{cfgServiceURL, cfgClientID, cfgClientSecret}

		// check if any of the unsupported parameters is specified
		var errList []string
		for _, parameter := range unsupported {
			_, hasValue := data.GetOk(parameter)
			if hasValue {
				errList = append(errList, parameter)
			}
		}
		if len(errList) != 0 {
			errMsg = "The parameter(s) " + strings.Join(errList, ",") + " should not be specified when machine credential is used"
			return
		}
	} else {
		// check all parameters that should/must be specified
		if hasServiceURL {
			config.ServiceURL = vServiceURL.(string) //nolint:forcetypeassert
		} else if req.Operation == logical.CreateOperation {
			config.ServiceURL = data.Get(cfgServiceURL).(string) //nolint:forcetypeassert
		}
		if config.ServiceURL == "" {
			errMsg = "config parameter `service_url` cannot be empty"
			return
		}

		if hasClientID {
			config.ClientID = vClientID.(string) //nolint:forcetypeassert
		} else if req.Operation == logical.CreateOperation {
			config.ClientID = data.Get(cfgClientID).(string) //nolint:forcetypeassert
		}
		if config.ClientID == "" {
			errMsg = "config parameter `client_id` cannot be empty"
			return
		}

		if hasClientSecret {
			config.ClientSecret = vClientSecret.(string) //nolint:forcetypeassert
		} else if req.Operation == logical.CreateOperation {
			config.ClientSecret = data.Get(cfgClientSecret).(string) //nolint:forcetypeassert
		}
		if config.ClientSecret == "" {
			errMsg = "config parameter `client_secret` cannot be empty"
			return
		}
	}

	if hasAppID {
		config.AppID = vAppID.(string) //nolint:forcetypeassert
	} else if req.Operation == logical.CreateOperation {
		config.AppID = data.Get(cfgAppID).(string) //nolint:forcetypeassert
	}

	if config.AppID == "" {
		if config.UseMachineCred {
			config.AppID = defaultAppIDForDMC
		} else {
			config.AppID = defaultAppID
		}
	}

	if hasScope {
		config.Scope = vScope.(string) //nolint:forcetypeassert
	} else if req.Operation == logical.CreateOperation {
		config.Scope = data.Get(cfgScope).(string) //nolint:forcetypeassert
	}

	if config.Scope == "" {
		config.Scope = defaultScope
	}

	return
}
