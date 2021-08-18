package centrify

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRolesList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "roles/" + framework.GenericNameWithAtRegex("rolename"),
		Fields: map[string]*framework.FieldSchema{
			"rolename": {
				Type:        framework.TypeString,
				Description: "Name for this role.",
				Required:    true,
			},
			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Policies of this role.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleCreateUpdate},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleCreateUpdate},
		},

		ExistenceCheck: b.roleExistenceCheck,

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
	return p
}

func (b *backend) roleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	roleEntry, err := b.role(ctx, req.Storage, d.Get("rolename").(string))
	if err != nil {
		return false, err
	}

	return roleEntry != nil, nil
}

func (b *backend) role(ctx context.Context, s logical.Storage, rolename string) (*RoleEntry, error) {
	if rolename == "" {
		return nil, fmt.Errorf("missing rolename")
	}

	entry, err := s.Get(ctx, "role/"+strings.ToLower(rolename))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result RoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) setRole(ctx context.Context, s logical.Storage, rolename string, roleEntry *RoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+rolename, roleEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+strings.ToLower(d.Get("rolename").(string)))
	return nil, err
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := b.role(ctx, req.Storage, strings.ToLower(d.Get("rolename").(string)))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]interface{}{}

	if len(role.Policies) > 0 {
		data["policies"] = role.Policies
	}
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rolename := strings.ToLower(d.Get("rolename").(string))
	roleEntry, err := b.role(ctx, req.Storage, rolename)
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &RoleEntry{}
	}

	roleEntry.Policies = policyutil.ParsePolicies(d.Get("policies"))

	return nil, b.setRole(ctx, req.Storage, rolename, roleEntry)
}

type RoleEntry struct {
	Policies []string
}

const pathRoleHelpSyn = `
Manage role policies.
`

const pathRoleHelpDesc = `
This endpoint allows you to create, read, update, and delete policies for roles.
`
