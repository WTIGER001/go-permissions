package jsonstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func TestJSONStore_CRUD_HappyPaths(t *testing.T) {
	ctx := context.Background()
	
	dir, err := os.MkdirTemp("", "jsonstore_test_*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	
	path := filepath.Join(dir, "store.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Snapshot
	snap := store.Snapshot()
	if snap.Grants == nil {
		t.Fatalf("Snapshot returned nil grants")
	}

	// Role Management
	role := permissions.Role{ID: "role.test", Name: "Test"}
	if err := store.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.UpdateRole(ctx, role); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	
	if err := store.DeleteRole(ctx, "role.test"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}

	defs, err := store.RoleDefinitions(ctx)
	if err != nil {
		t.Fatalf("RoleDefinitions: %v", err)
	}
	if len(defs) != 0 {
		t.Fatalf("Expected 0 role defs, got %d", len(defs))
	}

	def, err := store.RoleDefinition(ctx, "r1")
	if err != nil || def.ID != "r1" {
		t.Fatalf("RoleDefinition: %v", err)
	}

	// Grant Management
	grant := permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u1", PermissionName: "p1", TeamScope: "*"}
	if err := store.CreateGrant(ctx, grant); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	
	// AssignRole
	if err := store.AssignRole(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u1"}, "role.test", nil); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	// Wrappers
	grants, err := store.GrantsForPrincipal(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u1"})
	if err != nil {
		t.Fatalf("GrantsForPrincipal: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("Expected 1 grant, got %d", len(grants))
	}

	hits, err := store.PrincipalsWithGrant(ctx, permissions.Request{Perm: "p1"})
	if err != nil {
		t.Fatalf("PrincipalsWithGrant: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("Expected 1 principal hit, got %d", len(hits))
	}

	groups, err := store.ListKnownGroupIDs(ctx)
	if err != nil {
		t.Fatalf("ListKnownGroupIDs: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("Expected 0 groups, got %d", len(groups))
	}

	members, err := store.GetGroupMembers(ctx, "g1")
	if err != nil {
		t.Fatalf("GetGroupMembers: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("Expected 0 members, got %d", len(members))
	}

	inGroup, err := store.IsUserInGroup(ctx, "u1", "g1")
	if err != nil || inGroup {
		t.Fatalf("IsUserInGroup: %v, %v", err, inGroup)
	}

	assigns, err := store.ListRoleAssignmentsForUserAndGroups(ctx, "u1", nil)
	if err != nil {
		t.Fatalf("ListRoleAssignmentsForUserAndGroups: %v", err)
	}
	if len(assigns) != 1 {
		t.Fatalf("Expected 1 assignment, got %d", len(assigns))
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
