package examples

import (
	"context"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestCrossTeamContractor verifies one contractor can access only explicitly granted teams.
func TestCrossTeamContractor(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	identity.TeamMembership = map[string][]inmemory.Entry{
		"11": {
			{
				ID:   "contractor-1",
				Kind: inmemory.UserMemberKind,
			},
		},
		"33": {
			{
				ID:   "contractor-1",
				Kind: inmemory.UserMemberKind,
			},
		},
	}

	perm := permissions.NewTeamPermission("tasks.view", "Tasks", "View Tasks", "Allows viewing tasks for a team.").WithChecker(svc)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "contractor-1", Effect: permissions.EffectAllow, TeamScope: "11", PermissionName: perm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "contractor-1", Effect: permissions.EffectAllow, TeamScope: "33", PermissionName: perm.ID()},
	)

	cases := []struct {
		team string
		want bool
	}{
		{"11", true},
		{"22", false},
		{"33", true},
		{"44", false},
	}
	for _, tc := range cases {
		if got := perm.Can(ctx, "contractor-1", tc.team); got != tc.want {
			t.Fatalf("team %s got %v want %v", tc.team, got, tc.want)
		}
	}
}
