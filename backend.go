package centrify

import (
	"context"
	"net/http"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	b.Logger().Debug("create backend context in factory")

	return b, nil
}

// Backend constructs an instance of Centrify Authentication plugin backend
func Backend() *backend { //nolint:revive
	var b backend

	b.Backend = &framework.Backend{
		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				"config",
			},
		},

		Paths: []*framework.Path{
			pathConfig(&b),
			pathVersion(&b),
			pathLogin(&b),
			pathUsers(&b),
			pathUsersList(&b),
			pathRoles(&b),
			pathRolesList(&b),
		},

		BackendType: logical.TypeCredential,
	}

	return &b
}

type backend struct {
	*framework.Backend
}

func (b *backend) Initialize(ctxt context.Context, req *logical.InitializationRequest) error {
	b.Logger().Info(
		"Centrify Authentication plugin",
		"version", pluginVersion,
		"build", pluginGitCommit,
	)
	return nil
}

func (b *backend) getHTTPFactory(config *config) func() *http.Client {
	httpClient := cleanhttp.DefaultClient

	if config.HTTPLogs {
		logger := b.Logger().Named("http-log-client")
		httpClient = newLogClient(logger)
	}
	return httpClient
}

const backendHelp = `
The "centrify" credential provider allows authentication using
a combination of a username and password via the Centrify Identity
Services Platform. 
`
