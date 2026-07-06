package examples

import (
	"context"
	"sort"
		"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestFinopsReporting validates system-level and team-level FinOps reporting grants with role ownership queries.
func TestFinopsReporting(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	systemPerm := permissions.NewSystemPermission("finops.system.report.view", "FinOps", "View System Cost Report", "Allows viewing system-wide cost reporting.").WithChecker(svc)
	teamPerm := permissions.NewTeamPermission("finops.team.report.view", "FinOps", "View Team Cost Report", "Allows viewing team-level cost reporting.").WithChecker(svc)

	if err := svc.AllowUser(ctx, "alice", systemPerm.ID(), nil); err != nil {
		t.Fatalf("allow alice system: %v", err)
	}
	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "bob", Effect: permissions.EffectAllow, TeamScope: "101", PermissionName: teamPerm.ID()})
	if err := svc.AssignRoleToUser(ctx, "carol", "role.finops_team_reporter", nil); err != nil {
		t.Fatalf("assign role carol: %v", err)
	}
	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.finops_team_reporter", Effect: permissions.EffectAllow, TeamScope: "202", PermissionName: teamPerm.ID()})

	if got := systemPerm.Can(ctx, "alice"); got != true {
		t.Fatalf("alice system got %v want true", got)
	}
	if got := systemPerm.Can(ctx, "bob"); got != false {
		t.Fatalf("bob system got %v want false", got)
	}
	if got := teamPerm.Can(ctx, "bob", "101"); got != true {
		t.Fatalf("bob team 101 got %v want true", got)
	}
	if got := teamPerm.Can(ctx, "bob", "202"); got != false {
		t.Fatalf("bob team 202 got %v want false", got)
	}
	if got := teamPerm.Can(ctx, "carol", "202"); got != true {
		t.Fatalf("carol team 202 got %v want true", got)
	}
	if got := teamPerm.Can(ctx, "carol", "303"); got != false {
		t.Fatalf("carol team 303 got %v want false", got)
	}
	if got := teamPerm.Can(ctx, "dave", "101"); got != false {
		t.Fatalf("dave team 101 got %v want false", got)
	}

	systemHits, err := svc.PrincipalsWithPermission(ctx, "", "", systemPerm.ID())
	if err != nil {
		t.Fatalf("system hits: %v", err)
	}
	systemLabels := make([]string, 0, len(systemHits))
	for _, hit := range systemHits {
		systemLabels = append(systemLabels, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(systemLabels)
	if len(systemLabels) != 1 || systemLabels[0] != "user:alice" {
		t.Fatalf("unexpected system owners: %v", systemLabels)
	}

	teamID := "202"
	teamHits, err := svc.PrincipalsWithPermission(ctx, teamID, "", teamPerm.ID())
	if err != nil {
		t.Fatalf("team hits: %v", err)
	}
	teamLabels := make([]string, 0, len(teamHits))
	for _, hit := range teamHits {
		teamLabels = append(teamLabels, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(teamLabels)
	if len(teamLabels) != 1 || teamLabels[0] != "role:role.finops_team_reporter" {
		t.Fatalf("unexpected team owners: %v", teamLabels)
	}
}
