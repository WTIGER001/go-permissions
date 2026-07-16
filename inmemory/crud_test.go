package inmemory

import (
	"context"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func TestInMemoryStore_CRUD_HappyPaths(t *testing.T) {
	ctx := context.Background()
	store := NewStore()

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
