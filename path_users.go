package centrify

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathUsersList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "users/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathUserList},
		},

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
}

func pathUsers(b *backend) *framework.Path {
	path := &framework.Path{
		Pattern: "users/" + framework.GenericNameWithAtRegex("username"),
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Username for this user.",
				Required:    true,
			},
			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Policies of this user.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathUserDelete},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathUserRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathUserCreateUpdate},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathUserCreateUpdate},
		},

		ExistenceCheck: b.userExistenceCheck,

		HelpSynopsis:    pathUserHelpSyn,
		HelpDescription: pathUserHelpDesc,
	}
	return path
}

func (b *backend) userExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	userEntry, err := b.user(ctx, req.Storage, d.Get("username").(string))
	if err != nil {
		return false, err
	}

	return userEntry != nil, nil
}

func (b *backend) user(ctx context.Context, s logical.Storage, username string) (*UserEntry, error) {
	if username == "" {
		return nil, fmt.Errorf("missing username")
	}

	entry, err := s.Get(ctx, "user/"+strings.ToLower(username))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result UserEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) setUser(ctx context.Context, s logical.Storage, username string, userEntry *UserEntry) error {
	entry, err := logical.StorageEntryJSON("user/"+username, userEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) pathUserList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	users, err := req.Storage.List(ctx, "user/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(users), nil
}

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "user/"+strings.ToLower(d.Get("username").(string)))
	return nil, err
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.user(ctx, req.Storage, strings.ToLower(d.Get("username").(string)))
	if err != nil || user == nil {
		return nil, err
	}

	data := map[string]interface{}{}

	if len(user.Policies) > 0 {
		data["policies"] = user.Policies
	}
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathUserCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
	userEntry, err := b.user(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}

	// Due to existence check, user will only be nil if it's a create operation
	if userEntry == nil {
		userEntry = &UserEntry{}
	}

	userEntry.Policies = policyutil.ParsePolicies(d.Get("policies"))

	return nil, b.setUser(ctx, req.Storage, username, userEntry)
}

type UserEntry struct {
	Policies []string
}

const pathUserHelpSyn = `
Manage users policies for Centrify PAS users.
`

const pathUserHelpDesc = `
This endpoint allows you to create, read, update, and delete policies for PAS users
that are allowed to authenticate via the Centrify login method.
`
