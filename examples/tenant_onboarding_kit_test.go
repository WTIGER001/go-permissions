package examples

import (
	"context"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestTenantOnboardingKit verifies a reusable tenant starter role bound to one team during onboarding.
func TestTenantOnboardingKit(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	viewPerm := permissions.NewTeamPermission("projects.view", "Projects", "View Projects", "Allows viewing projects for a team.").WithChecker(svc)
	createPerm := permissions.NewTeamPermission("projects.create", "Projects", "Create Projects", "Allows creating projects for a team.").WithChecker(svc)

	identity.TeamMembership = map[string][]inmemory.Entry{
		"555": {
			{
				ID:   "tenant-admin",
				Kind: inmemory.UserMemberKind,
			},
		},
	}

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.tenant_starter", Effect: permissions.EffectAllow, TeamScope: "555", PermissionName: "projects.view"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.tenant_starter", Effect: permissions.EffectAllow, TeamScope: "555", PermissionName: "projects.create"},
	)

	if err := svc.AssignRoleToUser(ctx, "tenant-admin", "role.tenant_starter", nil); err != nil {
		t.Fatalf("assign tenant starter role: %v", err)
	}
	view555, err := svc.HasTeamPermission(ctx, "tenant-admin", "555", "", viewPerm.ID())
	if err != nil {
		t.Fatalf("view team 555 error: %v", err)
	}
	if view555 != true {
		t.Fatalf("view team 555 got %v want true", view555)
	}
	create555, err := svc.HasTeamPermission(ctx, "tenant-admin", "555", "", createPerm.ID())
	if err != nil {
		t.Fatalf("create team 555 error: %v", err)
	}
	if create555 != true {
		t.Fatalf("create team 555 got %v want true", create555)
	}
	view777, err := svc.HasTeamPermission(ctx, "tenant-admin", "777", "", viewPerm.ID())
	if err != nil {
		t.Fatalf("view team 777 error: %v", err)
	}
	if view777 != false {
		t.Fatalf("view team 777 got %v want false", view777)
	}
}
