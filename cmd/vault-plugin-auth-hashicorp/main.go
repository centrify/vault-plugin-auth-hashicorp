package main

import (
	"os"

	log "github.com/hashicorp/go-hclog"

	centrify "github.com/centrify/vault-plugin-auth-hashicorp"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:]) //nolint: errcheck

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: centrify.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.L().Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
