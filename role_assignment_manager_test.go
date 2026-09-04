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
