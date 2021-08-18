package centrify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/centrify/cloud-golang-sdk/oauth"
	"github.com/centrify/cloud-golang-sdk/restapi"
	"github.com/centrify/platform-go-sdk/oauthhelper"
	"github.com/centrify/platform-go-sdk/utils"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// sourceHeader defines value of header used in REST API calls.
	sourceHeader = "vault-plugin-auth-centrify"

	// defaultAuthMode defines "resource owner" as default auth mode.
	defaultAuthMode = "ro"

	// curTokenVersion defines version of access token saved in metadata.
	// Change when "schema" is changed. The string must represent an integer.
	// No major/minor version.
	curTokenVersion = "1"

	// tokenChunkSize defines size of each chunk of token saved in metadata.
	tokenChunkSize = 510
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username of the user.",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password for this user.",
			},
			"mode": {
				Type:        framework.TypeString,
				Description: "Auth mode ('ro' for resource owner, 'cc' for credential client).",
				Default:     defaultAuthMode,
			},
			"token": {
				Type:        framework.TypeString,
				Description: "OAuth token",
			},
			"tokentype": {
				Type:        framework.TypeString,
				Description: "OAuth token type",
			},
			"ttl": {
				Type:        framework.TypeInt,
				Description: "TTL for OAuth token in seconds",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation:         &framework.PathOperation{Callback: b.pathLogin},
			logical.AliasLookaheadOperation: &framework.PathOperation{Callback: b.pathLoginAliasLookahead},
		},

		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
	DMCtoken := d.Get("token").(string)
	if DMCtoken == "" {
		if username == "" {
			return nil, fmt.Errorf("missing username")
		}
	} else {
		tokenType, ok := d.Get("tokentype").(string)
		if !ok || tokenType == "" {
			tokenType = "Bearer"
		}
		expiresIn, ok := d.Get("ttl").(int)
		if !ok || expiresIn == 0 {
			return nil, errors.New("TTL is required when token is used")
		}
		token := &oauth.TokenResponse{
			AccessToken:  DMCtoken,
			TokenType:    tokenType,
			ExpiresIn:    expiresIn,
			RefreshToken: "",
		}
		config, err := b.Config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		if config == nil {
			return nil, errors.New("centrify auth plugin configuration not set") //nolint:goerr113
		}
		HTTPClientFactory := b.getHTTPFactory(config)

		uinfo, err := b.getUserInfo(token, config.ServiceURL, HTTPClientFactory)
		if err != nil {
			return nil, err
		}
		b.Logger().Debug("centrify authenticated user", "userinfo", uinfo.username)
		username = uinfo.username
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}

func (b *backend) pathLogin( //nolint:funlen,gocognit,gocyclo,cyclop
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
	password := d.Get("password").(string)
	mode := d.Get("mode").(string)
	DMCtoken := d.Get("token").(string)

	loginUsingToken := DMCtoken != ""

	if DMCtoken == "" {
		if password == "" {
			return nil, fmt.Errorf("missing password")
		}

		if mode == "" {
			mode = defaultAuthMode
		}
	}

	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, errors.New("centrify auth plugin configuration not set") //nolint:goerr113
	}
	HTTPClientFactory := b.getHTTPFactory(config)

	if len(config.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, config.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	var token *oauth.TokenResponse

	appID := config.AppID
	scope := config.Scope

	if loginUsingToken {
		tokenType, ok := d.Get("tokentype").(string)
		if !ok || tokenType == "" {
			tokenType = "Bearer"
		}
		expiresIn, ok := d.Get("ttl").(int)
		if !ok || expiresIn == 0 {
			return nil, errors.New("TTL is required when token is used")
		}
		token = &oauth.TokenResponse{
			AccessToken:  DMCtoken,
			TokenType:    tokenType,
			ExpiresIn:    expiresIn,
			RefreshToken: "",
		}
	} else {
		var oclient *oauth.OauthClient
		var failure *oauth.ErrorResponse

		if mode == "cc" {
			b.Logger().Debug("Login for using client credential", "user", username)

			oclient, err = oauth.GetNewConfidentialClient(config.ServiceURL, username, password, HTTPClientFactory)
			oclient.SourceHeader = sourceHeader

			if err != nil {
				b.Logger().Debug("Cannot get oauth client", "error", err.Error())
				return nil, errors.New("cannot get Oauth client") //nolint:goerr113
			}

			token, failure, err = oclient.ClientCredentials(appID, scope)
		} else if mode == "ro" {
			b.Logger().Debug("Login for app using secret as resource owner")
			if config.UseMachineCred {
				// use Centrify Client to obtain the access token
				var accessToken, tokenType, refreshToken string
				var expiresIn uint32

				accessToken, tokenType, expiresIn, refreshToken, err = oauthhelper.GetResourceOwnerToken(appID, scope, username, password)
				if err == utils.ErrExpiredPublicKey {
					// expired public key, try again
					b.Logger().Debug("Centrify Client has new public/private key, retry")
					accessToken, tokenType, expiresIn, refreshToken, err = oauthhelper.GetResourceOwnerToken(appID, scope, username, password)
				}

				if err != nil {
					b.Logger().Debug("resource owner", "error", err.Error())
				} else {
					token = &oauth.TokenResponse{
						AccessToken:  accessToken,
						TokenType:    tokenType,
						ExpiresIn:    int(expiresIn),
						RefreshToken: refreshToken,
					}
				}
			} else {

				oclient, err = oauth.GetNewConfidentialClient(
					config.ServiceURL,
					config.ClientID,
					config.ClientSecret,
					HTTPClientFactory,
				)
				oclient.SourceHeader = sourceHeader

				if err != nil {
					b.Logger().Debug("Cannot get oauth client", "error", err.Error())
					return nil, errors.New("cannot get Oauth client") //nolint:goerr113
				}

				b.Logger().Debug("Ready to set request for resource owner", "appID", appID, "scope", scope, "header", oclient.Headers["Authorization"])
				token, failure, err = oclient.ResourceOwner(appID, scope, username, password)
				if err != nil {
					b.Logger().Debug("resource owner", "error in call", err.Error())
				}
				if failure != nil {
					b.Logger().Debug("resource owner", "failure response", failure.Error, "description", failure.Description)
				}
			}
		} else {
			return nil, fmt.Errorf("Invalid mode or no mode provided: %s", mode)
		}

		if err != nil {
			return nil, err
		}

		if failure != nil {
			return nil, fmt.Errorf("OAuth2 token request failed: %v", failure)
		}
	}

	uinfo, err := b.getUserInfo(token, config.ServiceURL, HTTPClientFactory)
	if err != nil {
		return nil, err
	}

	if loginUsingToken {
		username = uinfo.username
	}
	b.Logger().Debug("centrify authenticated user", "userinfo", uinfo.username, "token type", token.TokenType, "expiresIn", token.ExpiresIn)

	var rolePolicies []string
	if config.RolesAsPolicies {
		for _, role := range uinfo.roles {
			rolePolicies = append(rolePolicies, config.PolicyPrefix+strings.Replace(role, " ", "_", -1))
		}
		b.Logger().Debug("Based on RolesAsPolicies settings", "policies", rolePolicies)
	}

	user, err := b.user(ctx, req.Storage, username)
	if err == nil && user != nil && len(user.Policies) > 0 {
		config.TokenPolicies = append(config.TokenPolicies, user.Policies...)
		b.Logger().Debug("Based on user setting", "policies", user.Policies)
	}

	for _, role := range uinfo.roles {
		roleName := strings.Replace(role, " ", "_", -1)
		roleEntry, err := b.role(ctx, req.Storage, roleName)
		if err != nil {
			b.Logger().Error("Failed to load policies for role %s :", roleName, err)
			continue
		}
		if roleEntry != nil {
			rolePolicies = append(rolePolicies, roleEntry.Policies...)
		}
	}
	if len(rolePolicies) > 0 {
		b.Logger().Debug("Merged policies based on roles", "policies", rolePolicies)
		config.TokenPolicies = append(config.TokenPolicies, rolePolicies...)
	}

	b.Logger().Debug("After merging all policies", "token policies", config.TokenPolicies)
	resp := &logical.Response{}

	expiresIn := time.Duration(token.ExpiresIn) * time.Second
	ttl := config.TokenTTL
	if ttl == 0 || expiresIn < ttl {
		ttl = expiresIn
		if expiresIn < ttl {
			resp.AddWarning("Centrify token expiration less than configured token TTL, capping to Centrify token expiration")
		}
	}

	b.Logger().Debug("token", "size", len(token.AccessToken))
	auth := &logical.Auth{
		TokenPolicies: config.TokenPolicies,
		DisplayName:   username,
		LeaseOptions: logical.LeaseOptions{
			TTL:       time.Duration(token.ExpiresIn) * time.Second,
			Renewable: false,
		},
		Alias: &logical.Alias{
			Name:     username,
			Metadata: saveToken(token, tokenChunkSize),
		},
		Metadata: map[string]string{
			"username": username,
		},
		EntityID: strings.ToLower(uinfo.uuid),
	}

	config.PopulateTokenAuth(auth)
	auth.LeaseOptions.Renewable = false
	auth.LeaseOptions.TTL = ttl
	resp.Auth = auth

	b.Logger().Debug("Returned user information.", "Entity ID", resp.Auth.EntityID, "Alias", resp.Auth.Alias.Name)
	for _, role := range uinfo.roles {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: role,
		})
	}

	return resp, nil
}

type userinfo struct {
	uuid     string
	username string
	roles    []string
}

// getUserInfo returns list of user's roles, user uuid, user name
func (b *backend) getUserInfo(
	accessToken *oauth.TokenResponse,
	serviceURL string,
	httpFactory func() *http.Client,
) (*userinfo, error) {
	b.Logger().Debug("getting user information")
	uinfo := &userinfo{}

	restClient, err := restapi.GetNewRestClient(serviceURL, httpFactory)
	if err != nil {
		return nil, err
	}

	restClient.Headers["Authorization"] = accessToken.TokenType + " " + accessToken.AccessToken
	restClient.SourceHeader = sourceHeader

	// First call /security/whoami to get details on current user
	whoami, err := restClient.CallGenericMapAPI("/security/whoami", nil)
	if err != nil {
		return nil, err
	}
	if !whoami.Success {
		return nil, fmt.Errorf("failed to get user details: %s", whoami.Message)
	}
	uinfo.username = whoami.Result["User"].(string)
	uinfo.uuid = whoami.Result["UserUuid"].(string)

	// Now enumerate roles
	b.Logger().Debug("Getting user's role and admin rights")
	rolesAndRightsResult, err := restClient.CallGenericMapAPI("/usermgmt/GetUsersRolesAndAdministrativeRights", nil)
	if err != nil {
		return nil, err
	}

	uinfo.roles = make([]string, 0)

	if rolesAndRightsResult.Success {
		// Results is an array of map[string]interface{}
		var results = rolesAndRightsResult.Result["Results"].([]interface{})
		for _, v := range results {
			var resultItem = v.(map[string]interface{})
			var row = resultItem["Row"].(map[string]interface{})
			uinfo.roles = append(uinfo.roles, row["Name"].(string))
		}
	} else {
		b.Logger().Error("centrify: failed to get user roles", "error", rolesAndRightsResult.Message)
	}
	b.Logger().Debug("Got roles", "roles", uinfo.roles)
	return uinfo, nil
}

// saveToken saves the token in a string map. maxsize is the size limit for each string
func saveToken(token *oauth.TokenResponse, maxsize int) map[string]string {
	var result = make(map[string]string)
	var key string

	prefix := "access_token_"

	// save AccessToken
	origLen := len(token.AccessToken)
	index := 0
	for i := 0; i < origLen; i += maxsize {
		end := i + maxsize
		if end > origLen {
			end = origLen
		}
		key = fmt.Sprintf("%s%d", prefix, index)
		result[key] = token.AccessToken[i:end]
		index++
	}

	// save other fields of access token
	result["TokenVersion"] = curTokenVersion
	result["TokenType"] = token.TokenType
	result["ExpiresIn"] = strconv.Itoa(token.ExpiresIn)
	result["ExpiresAt"] = time.Now().UTC().Add(time.Second * time.Duration(token.ExpiresIn)).Format(time.ANSIC)

	// save refresh token
	prefix = "refresh_token_"
	origLen = len(token.RefreshToken)
	index = 0
	for i := 0; i < origLen; i += maxsize {
		end := i + maxsize
		if end > origLen {
			end = origLen
		}
		key = fmt.Sprintf("%s%d", prefix, index)
		result[key] = token.RefreshToken[i:end]
		index++
	}
	return result
}

const pathLoginSyn = `
Log in with a username and password.
`

const pathLoginDesc = `
This endpoint authenticates using a username and password against the Centrify Identity Services Platform.
`
