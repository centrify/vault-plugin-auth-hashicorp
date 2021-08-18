package centrify

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// configuration parameters
const (
	cfgAppID           = "app_id"
	cfgClientID        = "client_id"
	cfgClientSecret    = "client_secret"
	cfgPolicies        = "policies"
	cfgTokenPolicies   = "token_policies"
	cfgPolicyPrefix    = "policy_prefix"
	cfgRolesAsPolicies = "roles_as_policies"
	cfgScope           = "scope"
	cfgServiceURL      = "service_url"
	cfgUseMachCred     = "use_machine_credential"
	cfgHTTPLogs        = "http_logs"
)

func pathConfig(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			cfgClientID: {
				Type:        framework.TypeString,
				Description: "OAuth2 Client ID",
			},
			cfgClientSecret: {
				Type:        framework.TypeString,
				Description: "OAuth2 Client Secret",
			},
			cfgServiceURL: {
				Type:        framework.TypeString,
				Description: "Service URL (https://<tenant>.my.centrify.com)",
			},
			cfgAppID: {
				Type:        framework.TypeString,
				Description: "OAuth2 App ID",
				Default:     "vault_io_integration",
			},
			cfgScope: {
				Type:        framework.TypeString,
				Description: "OAuth2 App Scope",
				Default:     "vault_io_integration",
			},
			cfgPolicies: {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},
			cfgRolesAsPolicies: {
				Type:        framework.TypeBool,
				Description: "Use user's role list as policies, note that _ will be used in place of spaces.",
				Default:     false,
			},
			cfgUseMachCred: {
				Type:        framework.TypeBool,
				Description: "Use machine credential when plugin accesses Centrify Platform",
				Default:     false,
			},
			cfgPolicyPrefix: {
				Type:        framework.TypeString,
				Description: "Prefix for local policies those will be mapped to PAS roles.",
			},
			cfgHTTPLogs: {
				Type:        framework.TypeBool,
				Description: "Enables logging of HTTP requests. It can be useful for troubleshooting and support",
				Default:     false,
			},
		},

		ExistenceCheck: b.pathConfigExistCheck,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigCreateOrUpdate},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigCreateOrUpdate},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
		},

		HelpSynopsis: pathSyn,
	}
	tokenutil.AddTokenFieldsWithAllowList(p.Fields, []string{
		"token_bound_cidrs",
		"token_no_default_policy",
		"token_policies",
		"token_type",
		"token_ttl",
		"token_num_uses",
	})
	return p
}

func (b *backend) pathConfigExistCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return config != nil, nil
}

func (b *backend) pathConfigCreateOrUpdate(ctx context.Context,
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathConfigCreateOrUpdate", "operation", req.Operation)
	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &config{}
	}

	changed, errMsg := b.handleAuthParameters(cfg, req, data)
	if errMsg != "" {
		return logical.ErrorResponse(errMsg), nil
	}

	if changed && cfg.UseMachineCred {
		// some configuration information is changed and selects to
		// use machine credential, verify
		var tenantURL string
		var clientID string
		HTTPClientFactory := b.getHTTPFactory(cfg)

		tenantURL, clientID, _, err = b.checkMachCred(HTTPClientFactory)
		if err != nil {
			b.Logger().Debug("Error in checking machine credential")
			return logical.ErrorResponse(fmt.Sprintf("Error in verifying machine credential for machine: %v", err)), nil
		}
		b.Logger().Debug("Machine credential verified")
		cfg.ClientID = clientID
		cfg.ServiceURL = tenantURL
		cfg.ClientSecret = ""
	}

	val, ok := data.GetOk(cfgRolesAsPolicies)
	if ok {
		cfg.RolesAsPolicies = val.(bool) //nolint:forcetypeassert
	} else if req.Operation == logical.CreateOperation {
		cfg.RolesAsPolicies = data.Get(cfgRolesAsPolicies).(bool) //nolint:forcetypeassert
	}

	val, ok = data.GetOk(cfgPolicyPrefix)
	if ok {
		cfg.PolicyPrefix = val.(string) //nolint:forcetypeassert
	} else if req.Operation == logical.CreateOperation {
		cfg.PolicyPrefix = data.Get(cfgPolicyPrefix).(string) //nolint:forcetypeassert
	}

	val, ok = data.GetOk(cfgPolicies)
	if ok {
		cfg.Policies = policyutil.ParsePolicies(val)
	}
	// Note: No need to set default for cfg.Policies

	val, ok = data.GetOk(cfgHTTPLogs)
	if ok {
		if v, ok := val.(bool); ok {
			cfg.HTTPLogs = v
		}
	} else if req.Operation == logical.CreateOperation {
		if v, ok := data.Get(cfgHTTPLogs).(bool); ok {
			cfg.HTTPLogs = v
		}
	}

	if err := cfg.ParseTokenFields(req, data); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if err := tokenutil.UpgradeValue(data, cfgPolicies, cfgTokenPolicies, &cfg.Policies, &cfg.TokenPolicies); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	cfg.TokenPolicies = policyutil.SanitizePolicies(cfg.TokenPolicies, false)

	// We want to normalize the service url to https://
	// The configuration parameter may not have https:// or http:// prefix
	// So we force it to have no trailing / and always start with https://
	normalizedURL := strings.TrimPrefix(cfg.ServiceURL, "http://")
	normalizedURL = strings.TrimPrefix(normalizedURL, "https://")
	normalizedURL = strings.TrimSuffix(normalizedURL, "/")

	url, err := url.Parse("https://" + normalizedURL)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("config parameter 'service_url' is not a valid url: %s", err.Error())), nil
	}

	cfg.ServiceURL = url.String()

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	d := map[string]interface{}{
		cfgClientID:        config.ClientID,
		cfgServiceURL:      config.ServiceURL,
		cfgAppID:           config.AppID,
		cfgScope:           config.Scope,
		cfgRolesAsPolicies: config.RolesAsPolicies,
		cfgPolicies:        config.Policies,
		cfgPolicyPrefix:    config.PolicyPrefix,
		cfgUseMachCred:     config.UseMachineCred,
		cfgHTTPLogs:        config.HTTPLogs,
	}

	config.PopulateTokenData(d)
	delete(d, "token_explicit_max_ttl")
	delete(d, "token_max_ttl")
	delete(d, "token_period")

	if len(config.Policies) > 0 {
		d["policies"] = d["token_policies"]
	}

	return &logical.Response{
		Data: d,
	}, nil
}

// Config returns the configuration for this backend.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result config

	if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("error reading configuration: %w", err)
	}

	if len(result.TokenPolicies) == 0 && len(result.Policies) > 0 {
		result.TokenPolicies = result.Policies
	}
	return &result, nil
}

type config struct {
	tokenutil.TokenParams

	ClientID        string   `json:"client_id" structs:"client_id" mapstructure:"client_id"`
	ClientSecret    string   `json:"client_secret" structs:"client_secret" mapstructure:"client_secret"`
	ServiceURL      string   `json:"service_url" structs:"service_url" mapstructure:"service_url"`
	AppID           string   `json:"app_id" structs:"app_id" mapstructure:"app_id"`
	Scope           string   `json:"scope" structs:"scope" mapstructure:"scope"`
	Policies        []string `json:"policies" structs:"policies" mapstructure:"policies"`
	RolesAsPolicies bool     `json:"roles_as_policies" structs:"roles_as_policies" mapstructure:"roles_as_policies"`
	UseMachineCred  bool     `json:"use_machine_credential" structs:"use_machine_credential" mapstructure:"use_machine_credential"`
	PolicyPrefix    string   `json:"policy_prefix" structs:"policy_prefix" mapstructure:"policy_prefix"`
	HTTPLogs        bool     `json:"http_logs" structs:"http_logs" mapstructure:"http_logs"`
}

const pathSyn = `
This path allows you to configure the centrify auth provider to interact with the Centrify Identity Services Platform
for authenticating users.  
`
