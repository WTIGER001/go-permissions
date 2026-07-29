package postgres

import (
	"context"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func TestPostgres_CRUD_Roles(t *testing.T) {
	store, pool := newTestStore(t)
	defer pool.Close()
	ctx := context.Background()

	// Create Role
	role1 := permissions.Role{
		ID:          "role.crud_tester",
		Name:        "CRUD Tester",
		Scope:       permissions.RoleScopeTeam,
		Tags:        []string{"test", "crud"},
		Permissions: []string{"test.read", "test.write"},
	}
	err := store.CreateRole(ctx, role1)
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	// Read Role
	role, err := store.RoleDefinition(ctx, "role.crud_tester")
	if err != nil {
		t.Fatalf("RoleDefinition failed: %v", err)
	}
	if role.Name != "CRUD Tester" {
		t.Errorf("Unexpected role name: %s", role.Name)
	}
	if role.Scope != permissions.RoleScopeTeam {
		t.Errorf("Unexpected role scope: %s", role.Scope)
	}
	if len(role.Tags) != 2 || role.Tags[0] != "test" || role.Tags[1] != "crud" {
		t.Errorf("Unexpected role tags: %v", role.Tags)
	}

	// Update Role
	role.Name = "CRUD Tester Updated"
	role.Scope = permissions.RoleScopeSystem
	role.Tags = []string{"test", "updated"}
	err = store.UpdateRole(ctx, role)
	if err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}
	role, _ = store.RoleDefinition(ctx, "role.crud_tester")
	if role.Name != "CRUD Tester Updated" {
		t.Errorf("UpdateRole didn't stick")
	}
	if role.Scope != permissions.RoleScopeSystem {
		t.Errorf("UpdateRole scope didn't stick: %s", role.Scope)
	}
	if len(role.Tags) != 2 || role.Tags[1] != "updated" {
		t.Errorf("UpdateRole tags didn't stick: %v", role.Tags)
	}

	// RoleDefinitions
	roles, err := store.RoleDefinitions(ctx)
	if err != nil {
		t.Fatalf("RoleDefinitions failed: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("Expected 1 role, got %d", len(roles))
	}

	// Delete Role
	err = store.DeleteRole(ctx, "role.crud_tester")
	if err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}
	_, err = store.RoleDefinition(ctx, "role.crud_tester")
	if err == nil {
		t.Errorf("Expected error after deleting role, got nil")
	}
}

func TestPostgres_CRUD_GrantsAndAssignments(t *testing.T) {
	store, pool := newTestStore(t)
	defer pool.Close()
	ctx := context.Background()

	// AssignRole
	uRef := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u-crud"}
	err := store.AssignRole(ctx, uRef, "role.dummy", nil)
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}
	assigns, err := store.RoleAssignmentsForPrincipal(ctx, uRef)
	if err != nil || len(assigns) != 1 {
		t.Fatalf("RoleAssignmentsForPrincipal failed or returned unexpected: %+v", assigns)
	}

	// CreateGrant
	err = store.CreateGrant(ctx, permissions.Grant{
		OwnerKind:      permissions.PrincipalUser,
		OwnerID:        "u-crud",
		TeamScope:      "*",
		PermissionName: "test.direct",
		Effect:         permissions.EffectAllow,
	})
	if err != nil {
		t.Fatalf("CreateGrant failed: %v", err)
	}

	// GrantsForPrincipal
	grants, err := store.GrantsForPrincipal(ctx, uRef)
	if err != nil || len(grants) != 1 {
		t.Fatalf("GrantsForPrincipal failed or returned unexpected: %+v", grants)
	}

	// PrincipalsWithGrant
	hits, err := store.PrincipalsWithGrant(ctx, permissions.Request{Perm: "test.direct"})
	if err != nil || len(hits) != 1 {
		t.Fatalf("PrincipalsWithGrant failed or returned unexpected: %+v", hits)
	}

	// DeleteGrantsForOwner
	err = store.DeleteGrantsForOwner(ctx, permissions.PrincipalUser, "u-crud")
	if err != nil {
		t.Fatalf("DeleteGrantsForOwner failed: %v", err)
	}
	grants, _ = store.GrantsForPrincipal(ctx, uRef)
	if len(grants) != 0 {
		t.Errorf("Grants should be deleted, got %d", len(grants))
	}
}

func TestPostgres_CRUD_BuiltIns(t *testing.T) {
	store, pool := newTestStore(t)
	defer pool.Close()
	ctx := context.Background()

	err := store.DisableBuiltInRole(ctx, "builtin.test")
	if err != nil {
		t.Fatalf("DisableBuiltInRole failed: %v", err)
	}
	disabled, err := store.DisabledBuiltInRoles(ctx)
	if err != nil || len(disabled) != 1 || disabled[0] != "builtin.test" {
		t.Fatalf("DisabledBuiltInRoles failed or unexpected: %+v", disabled)
	}

	err = store.EnableBuiltInRole(ctx, "builtin.test")
	if err != nil {
		t.Fatalf("EnableBuiltInRole failed: %v", err)
	}
	disabled, _ = store.DisabledBuiltInRoles(ctx)
	if len(disabled) != 0 {
		t.Fatalf("Expected empty disabled roles after EnableBuiltInRole")
	}
}

func TestPostgres_ListGrants(t *testing.T) {
	store, pool := newTestStore(t)
	defer pool.Close()
	ctx := context.Background()

	// Seed some grants for list queries
	store.CreateGrants(ctx, []permissions.Grant{
		{OwnerKind: permissions.PrincipalUser, OwnerID: "u1", TeamScope: "t1", PermissionName: "app.read", Effect: permissions.EffectAllow},
		{OwnerKind: permissions.PrincipalUser, OwnerID: "u1", TeamScope: "t2", PermissionName: "app.write", Effect: permissions.EffectAllow},
		{OwnerKind: permissions.PrincipalGroup, OwnerID: "g1", TeamScope: "*", PermissionName: "app.admin", Effect: permissions.EffectAllow},
		{OwnerKind: permissions.PrincipalGroup, OwnerID: "g1", TeamScope: "*", PermissionName: "sys.view", Effect: permissions.EffectAllow},
	})

	// Query 1: By Principal
	res, err := store.ListGrants(ctx, permissions.GrantQuery{
		Principals: []permissions.PrincipalRef{{Kind: permissions.PrincipalUser, ID: "u1"}},
	})
	if err != nil {
		t.Fatalf("ListGrants failed: %v", err)
	}
	if res.TotalCount != 2 {
		t.Errorf("Expected 2 grants for u1, got %d", res.TotalCount)
	}

	// Query 2: By Team
	res, err = store.ListGrants(ctx, permissions.GrantQuery{
		TeamScopes: []string{"t1"},
	})
	if err == nil && res.TotalCount != 1 {
		t.Errorf("Expected 1 grant for t1, got %d", res.TotalCount)
	}

	// Query 3: Prefix Match
	res, err = store.ListGrants(ctx, permissions.GrantQuery{
		PermissionPrefix: "app.",
	})
	if err == nil && res.TotalCount != 3 {
		t.Errorf("Expected 3 grants for app. prefix, got %d", res.TotalCount)
	}

	// Query 4: Permissions exactly
	res, err = store.ListGrants(ctx, permissions.GrantQuery{
		Permissions: []string{"sys.view"},
	})
	if err == nil && res.TotalCount != 1 {
		t.Errorf("Expected 1 grant for sys.view, got %d", res.TotalCount)
	}
	
	// Query 5: Pagination
	res, err = store.ListGrants(ctx, permissions.GrantQuery{
		Limit: 2,
	})
	if err == nil {
		if len(res.Grants) != 2 {
			t.Errorf("Expected exactly 2 results for limit, got %d", len(res.Grants))
		}
		if res.TotalCount != 4 {
			t.Errorf("Expected total count 4, got %d", res.TotalCount)
		}
		if res.NextCursor == "" {
			t.Errorf("Expected next cursor to be set")
		}
		
		// Follow cursor
		res2, err := store.ListGrants(ctx, permissions.GrantQuery{
			Limit: 2,
			Cursor: res.NextCursor,
		})
		if err == nil {
			if len(res2.Grants) != 2 {
				t.Errorf("Expected exactly 2 results for page 2, got %d", len(res2.Grants))
			}
		}
	}
}
