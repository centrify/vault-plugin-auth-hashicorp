# Vault Plugin: Centrify Identity Platform Auth Backend

# PUBLIC ARCHIVE

> ***NOTE***
> This repo is archived.
> This is still available under the licensing terms, but is not being actively developed or updated any further. Please see [DelineaXPM](https://github.com/DelineaXPM) for active projects.

This is a standalone backend plugin for use with [HashiСorp Vault][vault-gh].
This plugin allows for Centrify Identity Platform users accounts to authenticate with Vault.

## Quick Links
 - Vault Website: https://www.vaultproject.io
 - Main Project Github: https://www.github.com/hashicorp/vault

## Table of Contents

- [Getting Started](#getting-started)
- [Setup](#setup)
- [Usage](#usage)
- [Developing](#developing)

## Getting Started

This is a [Vault plugin][vault-plugins] and is meant to work with Vault. This guide
assumes you have already installed Vault and have a basic understanding of how Vault
works.

Otherwise, read this guide first on how to [get started with Vault][vault-get-started].

To learn specifically about how plugins work, see documentation on [Vault plugins][vault-plugins].

## Setup

Before the plugin can authenticate users, both the plugin and your cloud service tenant
must be configured correctly. Please note that this plugin requires the Centrify Cloud
Identity Service version 17.11 or newer.

1. Enable the plugin

```
# First, make sure plugin is registered and available in the catalog:
$ vault plugin list | grep centrify

# Now enable the plugin:
$ vault auth enable centrify
```

2. Configure your tenant and the plugin

There are two ways to configure PAS to enable this authentication plugin:
 - [Create an OAuth2 Confidential Client for the plugin](#use-oauth2-confidential-client-approach)
 - [Leverage Centrify Client](#integration-with-centrify-client)

Going forward, this plugin will be more integrated and leverage additional capabilities
of Centrify Client.  We recommend customers to start migration to use this new approach.
The "OAuth2 Confidential Client" approach remains for backward compatibility but some
functionalities may not be supported in the future.


### Use OAuth2 Confidential Client approach
#### Create an OAuth2 Confidential Client

An OAuth2 Confidentical Client is a Centrify Directory User.

- Users -> Add User
  - Login Name: vault_integration@<yoursuffix>
  - Display Name: Vault Integration Confidential Client
  - Check the "Is OAuth confidentical client" box
  - Password Type: Generated (be sure to copy the value, you will need it later)
  - Create User

#### Create a Role

To scope the users who can authenticate to vault, and to allow our Confidential Client
access, we will create a role.

- Roles -> Add Role
  - Name: Vault Integration
  - Members -> Add
    - Search for and add the vault_integration@<yoursuffix> user
    - Additionally add any roles/groups/users who should be able to authenticate to vault
  - Save

#### Create an OAuth2 Client Application
- Apps -> Add Web Apps -> Custom -> OAuth2 Client
- Configure the added application
  - Description:
    - Application ID: "vault_io_integration" 
    - Application Name: "Vault Integration"
  - General Usage:
    - Client ID Type -> Confidential (must be OAuth client)
  - Tokens:
    - Token Type: JwtRS256
    - Auth methods: Client Creds + Resource Owner
  - Scope
    - Add a single scope named "vault_io_integration" with the following regexes:
      - usermgmt/getusersrolesandadministrativerights
      - security/whoami
      - secrets/
      - privilegeddata/
  - User Access
    - Add the previously created "Vault Integration" role
  - Save

#### Configuring the Vault Plugin

As an administrative vault user, you can read/write the Centrify plugin configuration
using the /auth/centrify/config path:

```sh
$ vault write auth/centrify/config \
    service_url=https://<tenantid>.my.centrify.com \
    client_id=vault_integration@<yoursuffix> \
    client_secret=<password copied earlier> \
    app_id=vault_io_integration \
    scope=vault_io_integration
```
### Integration with Centrify Client

#### Centrify Client setup

You need to install version 2.15 (or later) of Centrify Client and enroll the client
to PAS with feature DMC (Delegated Machine Credentials) (use "-F all" or "-F DMC" in
cenroll command)

##### Create a Role

Create a role for all the users that you want to allow login to vault:

- Roles -> Add Role
  - Name: Vault users
  - Members -> Add
    - Add any roles/groups/users who should be able to authenticate to vault
  - Save

#### Create a web application that represents the vault

Note: ThycoticCentrify may automate this step in this future.

- Apps -> Add Web Apps -> Custom -> OAuth2 Client
- Configure the added application
  - Description:
    - Application ID: "vault_user" 
    - Application Name: "Vault Users"
  - General Usage:
    - Client ID Type -> Confidential (must be OAuth client)
  - Tokens:
    - Token Type: JwtRS256
    - Auth methods: Resource Owner
  - Scope
    - Add a single scope named "vault_io_integration" with the following regexes:
      - usermgmt/getusersrolesandadministrativerights
      - security/whoami
      - secrets/
      - privilegeddata/
  - User Access
    - Add the previously created "Vault users" role
  - Save

#### Configure the plugin

You need to use the vault command "vault write auth/centrify/config" to set the following
configuration parameters:

- use_machine_credential: true
- app_id: \<the name of the web application created above\>.  Default: vault_user
- scope: \<the scope defined in the web application above\>. Default: vault_io_integration

## Usage

### Authenticating

As a valid user of your tenant, in the appropriate role for accessing the Vault
Integration app, you can now authenticate to the vault:

```sh
$ vault auth -method=centrify username=<your username>
```

Your vault token will be valid for the length of time defined in the app's token lifetime
configuration (default 5 hours).

### User policies

You can associate policies with users and do CRUD operations against them. For example:
```
vault write auth/centrify/users/admin@acme.com policies="policyA, policyB"
vault read auth/centrify/users/admin@acme.com
vault list auth/centrify/users
vault delete auth/centrify/users/admin@acme.com
```

### Role policies

You can associate policies with roles and do CRUD operations against them. For example:
```
vault write auth/centrify/roles/roleName policies="policyA, policyB"
vault read auth/centrify/roles/roleName
vault list auth/centrify/roles
vault delete auth/centrify/roles/roleName
```

### Version

You can read the version of the plugin using:
```
vault read auth/centrify/version
```

## Developing

If you wish to work on this plugin, you'll first need [Go][go] installed on your machine
(version 1.16+ is *required*).

Set the directory where to save the plugin:
```
$ export VAULT_PLUGINS_DIR="/tmp/vault-plugins"
```

Build the plugin:
```
# make dev BINDIR=${VAULT_PLUGINS_DIR}
```

For local development, you can run Vault server in development mode:
```
$ sudo vault server \
    -dev \
    -dev-root-token-id=root \
    -dev-no-store-token \
    -dev-plugin-dir=${VAULT_PLUGINS_DIR} \
    -log-level=debug
```

Note that running the Vault server as privileged user (using `sudo`) is required for
communication with the Centrify Client.

Now you can enable the plugin:
```
$ vault auth enable centrify
```

Verify plugin version using:
```
$ vault read auth/centrify/version
```

### Testing

Prepare test configuration file:
```
$ cat <<EOF > ./testconfig.json
{
  "TenantURL": "<tenant_url>",
  "Marks": ["integration"],
  "ClientID": "<client_id>",
  "ClientSecret": "<client_secret>",
  "AppID": "<app_id>",
  "Scope": "<scope>",
  "PASuser": { "Username": "<username>", "Password": "<password>" },
  "PolicyChangeUser": { "Username": "<username>", "Password": "<password>" },
  "HTTPProxyURL": "<proxy-url>"
}
EOF
```

Run the tests:
```
$ make test
```

Or specify different location of test configuration file:
```
$ make test TESTCONF_FILE=../testconfig.json
```


[vault-gh]: https://www.github.com/hashicorp/vault
[vault-plugins]: https://www.vaultproject.io/docs/internals/plugins.html
[vault-get-started]: https://www.vaultproject.io/intro/getting-started/install.html
[vault-plugin-dir]: https://www.vaultproject.io/docs/configuration/index.html#plugin_directory
[vault-catalog]: https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog
[go]: https://www.golang.org
