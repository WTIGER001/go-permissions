package permissions_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

func setupRoleAssignmentManagerTest(t *testing.T) (*permissions.RoleAssignmentManager, []permissions.Role, context.Context) {
	store := inmemory.NewStore()
	idp := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, idp)
	ctx := context.Background()
	reg := permissions.NewPermissionRegistry()

	perm1 := permissions.PermissionDefinition{
		ID:        "perm_1",
		Namespace: "ns_1",
	}
	perm2 := permissions.PermissionDefinition{
		ID:        "perm_2",
		Namespace: "ns_1",
	}
	reg.Register(perm1)
	reg.Register(perm2)

	role1 := permissions.Role{
		ID:          "role_1",
		Name:        "role_1",
		Permissions: []string{perm1.ID},
	}
	role2 := permissions.Role{
		ID:          "role_2",
		Name:        "role_2",
		Permissions: []string{perm2.ID},
	}
	svc.AddBuiltInRole(ctx, role1)
	svc.AddBuiltInRole(ctx, role2)

	rm := permissions.NewRoleAssignmentManager(svc, []string{role1.ID, role2.ID}, nil, nil)

	return rm, []permissions.Role{role1, role2}, ctx
}

func TestRoleAssignmentManager_CannotAddSelfRule(t *testing.T) {
	rm, roles, ctx := setupRoleAssignmentManagerTest(t)
	rm.AddAssignmentRule(permissions.CannotAddSelfRule{RoleIDs: []string{roles[0].ID}})

	// --- Setup principals ---
	alice := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "alice"}
	//bob := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "bob"}
	//admin := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "admin"}

	err := rm.AddRoles(ctx, alice, []string{roles[0].ID}, &alice)
	if err == nil {
		t.Fatalf("expected error when alice adding alice to role2")
	}
}

func TestRoleAssignmentManager_CannotCombineRolesRule(t *testing.T) {
	rm, roles, ctx := setupRoleAssignmentManagerTest(t)
	rm.AddAssignmentRule(permissions.CannotCombineRolesRule{RoleA: roles[0].ID, RoleB: roles[1].ID})

	// --- Setup principals ---
	alice := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "alice"}
	//bob := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "bob"}
	//admin := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "admin"}

	err := rm.AddRoles(ctx, alice, []string{roles[0].ID, roles[1].ID}, &alice)
	if err == nil {
		t.Fatalf("expected error when alice adding alice to role1 & role2")
	}
	fmt.Println(err.Error())
}

func TestRoleAssignmentManager_RequireAtLeastRuleCountsTeams(t *testing.T) {
	rm, roles, ctx := setupRoleAssignmentManagerTest(t)
	rm.AddAssignmentRule(permissions.RequireAtLeastRule{RoleID: roles[0].ID, Min: 1})
	team := permissions.PrincipalRef{Kind: permissions.PrincipalTeam, ID: "team-1"}

	if err := rm.AddRoles(ctx, team, []string{roles[0].ID}, nil); err != nil {
		t.Fatalf("AddRoles: %v", err)
	}
	if err := rm.RemoveRoles(ctx, team, []string{roles[0].ID}, nil); err == nil {
		t.Fatal("expected removal of the last team assignment to violate RequireAtLeastRule")
	}
}

func TestRoleAssignmentManager_CleanupTeamRoleAssignments(t *testing.T) {
	store := inmemory.NewStore()
	svc := permissions.NewService(store, inmemory.NewIdentityProvider())
	ctx := context.Background()
	rm := permissions.NewRoleAssignmentManager(svc, []string{"role.managed"}, nil, nil)

	targetTeam := permissions.PrincipalRef{Kind: permissions.PrincipalTeam, ID: "team-1"}
	otherTeam := permissions.PrincipalRef{Kind: permissions.PrincipalTeam, ID: "team-2"}
	user := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "user-1"}
	group := permissions.PrincipalRef{Kind: permissions.PrincipalGroup, ID: "group-1"}

	for _, assignment := range []permissions.RoleAssignment{
		{RoleID: "role.managed", BindingValues: nil},
		{RoleID: "role.managed", BindingValues: map[string]any{"team": "team-1", "id": "object-1"}},
		{RoleID: "role.unmanaged", BindingValues: map[string]any{"team": "team-1"}},
	} {
		if err := svc.AssignRole(ctx, targetTeam, assignment.RoleID, assignment.BindingValues); err != nil {
			t.Fatalf("assign target team role %q: %v", assignment.RoleID, err)
		}
	}
	if err := svc.AssignRole(ctx, otherTeam, "role.managed", map[string]any{"team": "team-1"}); err != nil {
		t.Fatalf("assign other team role: %v", err)
	}
	if err := svc.AssignRole(ctx, user, "role.managed", map[string]any{"team": "team-1"}); err != nil {
		t.Fatalf("assign user role: %v", err)
	}
	if err := svc.AssignRole(ctx, group, "role.managed", map[string]any{"team": "team-1"}); err != nil {
		t.Fatalf("assign group role: %v", err)
	}

	if err := rm.CleanupTeamRoleAssignments(ctx, targetTeam.ID); err != nil {
		t.Fatalf("CleanupTeamRoleAssignments: %v", err)
	}

	targetAssignments, err := svc.RoleAssignmentsForPrincipal(ctx, targetTeam)
	if err != nil {
		t.Fatalf("target team assignments: %v", err)
	}
	if len(targetAssignments) != 1 || targetAssignments[0].RoleID != "role.unmanaged" {
		t.Fatalf("target team assignments = %+v, want only unmanaged role", targetAssignments)
	}

	for _, principal := range []permissions.PrincipalRef{otherTeam, user, group} {
		assignments, err := svc.RoleAssignmentsForPrincipal(ctx, principal)
		if err != nil {
			t.Fatalf("assignments for %s %q: %v", principal.Kind, principal.ID, err)
		}
		if len(assignments) != 1 || assignments[0].RoleID != "role.managed" {
			t.Fatalf("assignments for %s %q = %+v, want preserved managed role", principal.Kind, principal.ID, assignments)
		}
	}
}
