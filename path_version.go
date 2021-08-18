package centrify

import (
	"context"
	"fmt"
	"runtime"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// These values are overridden via ldflags.
//nolint: gochecknoglobals
var (
	pluginVersion   = "unknown-version"
	pluginGitCommit = "unknown-commit"
)

// List of keys in output.
const (
	verPluginVersion = "plugin_version"
	verGitCommit     = "git_commit"
	verGoVersion     = "go_version"
	verOSArch        = "os_arch"
)

func pathVersion(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "version",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathVersionRead,
			},
		},
		HelpSynopsis: pathVersionSyn,
	}
	return p
}

func (b *backend) pathVersionRead(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			verPluginVersion: pluginVersion,
			verGitCommit:     pluginGitCommit,
			verGoVersion:     runtime.Version(),
			verOSArch:        fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		},
	}, nil
}

const pathVersionSyn = `
This path allows you to read the version info about the Centrify Auth Plugin.
`
