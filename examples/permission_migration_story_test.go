package examples

import (
	"context"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestPermissionMigrationStory verifies dual-grant migration from a legacy permission ID to a replacement ID.
func TestPermissionMigrationStory(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	teamID := "808"
	teamScope := teamID
	oldPerm := permissions.NewTeamPermission("reports.read", "Reports", "Read Reports", "Allows reading reports.").WithChecker(svc)
	newPerm := permissions.NewTeamPermission("reports.view", "Reports", "View Reports", "Allows viewing reports.").WithChecker(svc)

	identity.TeamMembership = map[string][]inmemory.Entry{
		teamID: {
			{
				ID:   "legacy-user",
				Kind: inmemory.UserMemberKind,
			},
		},
	}

	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "legacy-user", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: oldPerm.ID()})

	if got := oldPerm.Can(ctx, "legacy-user", teamID); got != true {
		t.Fatalf("old before dual got %v want true", got)
	}
	if got := newPerm.Can(ctx, "legacy-user", teamID); got != false {
		t.Fatalf("new before dual got %v want false", got)
	}

	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "legacy-user", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: newPerm.ID()})

	if got := oldPerm.Can(ctx, "legacy-user", teamID); got != true {
		t.Fatalf("old after dual got %v want true", got)
	}
	if got := newPerm.Can(ctx, "legacy-user", teamID); got != true {
		t.Fatalf("new after dual got %v want true", got)
	}
}
