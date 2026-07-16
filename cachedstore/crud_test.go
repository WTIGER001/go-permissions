package cachedstore

import (
	"context"
	"testing"
	"time"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

func TestCachedStore_CRUD_HappyPaths(t *testing.T) {
	ctx := context.Background()
	base := inmemory.NewStore()
	store := NewStoreWithTTL(base, time.Minute)

	// Role Management
	role := permissions.Role{ID: "role.test", Name: "Test"}
	if err := store.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	role.Name = "Test Updated"
	if err := store.UpdateRole(ctx, role); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	
	if err := store.AddRoleInheritance(ctx, "role.test", "role.child"); err != nil {
		t.Fatalf("AddRoleInheritance: %v", err)
	}
	
	if err := store.DeleteRole(ctx, "role.test"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}

	// Grant Management
	grant := permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u1", PermissionName: "p1", TeamScope: "*"}
	if err := store.CreateGrant(ctx, grant); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if err := store.DeleteGrantsForOwner(ctx, permissions.PrincipalUser, "u1"); err != nil {
		t.Fatalf("DeleteGrantsForOwner: %v", err)
	}

	// BuiltIn Roles
	if err := store.DisableBuiltInRole(ctx, "builtin.test"); err != nil {
		t.Fatalf("DisableBuiltInRole: %v", err)
	}
	if err := store.EnableBuiltInRole(ctx, "builtin.test"); err != nil {
		t.Fatalf("EnableBuiltInRole: %v", err)
	}

	// ListGrants
	res, err := store.ListGrants(ctx, permissions.GrantQuery{})
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if res.TotalCount != 0 {
		t.Fatalf("Expected 0 grants, got %d", res.TotalCount)
	}
}
