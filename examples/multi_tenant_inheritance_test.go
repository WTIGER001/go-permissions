package examples

import (
	"context"
	"sort"
		"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestMultiTenantInheritance verifies role inheritance plus template bindings for tenant-specific grants.
func TestMultiTenantInheritance(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	viewPerm := permissions.NewTeamPermission("reports.view", "Reports", "View Team Reports", "Allows viewing reports for a team.").WithChecker(svc)
	exportPerm := permissions.NewTeamPermission("reports.export", "Reports", "Export Team Reports", "Allows exporting reports for a team.").WithChecker(svc)

	team1001 := "1001"
	team2002 := "2002"
	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.team_analyst_1001", Effect: permissions.EffectAllow, TeamScope: team1001, PermissionName: viewPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.team_analyst_2002", Effect: permissions.EffectAllow, TeamScope: team2002, PermissionName: viewPerm.ID()},
	)

	if err := svc.AssignRoleToUser(ctx, "anna", "role.team_analyst_1001", nil); err != nil {
		t.Fatalf("assign anna role: %v", err)
	}
	if err := svc.AssignRoleToUser(ctx, "ben", "role.team_analyst_2002", nil); err != nil {
		t.Fatalf("assign ben role: %v", err)
	}
	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "chris", Effect: permissions.EffectAllow, TeamScope: team1001, PermissionName: exportPerm.ID()})

	anna1001, err := svc.HasTeamPermission(ctx, "anna", team1001, "", viewPerm.ID())
	if err != nil {
		t.Fatalf("anna team1001 view error: %v", err)
	}
	if anna1001 != true {
		t.Fatalf("anna team1001 view got %v want true", anna1001)
	}
	anna2002, err := svc.HasTeamPermission(ctx, "anna", team2002, "", viewPerm.ID())
	if err != nil {
		t.Fatalf("anna team2002 view error: %v", err)
	}
	if anna2002 != false {
		t.Fatalf("anna team2002 view got %v want false", anna2002)
	}
	ben2002, err := svc.HasTeamPermission(ctx, "ben", team2002, "", viewPerm.ID())
	if err != nil {
		t.Fatalf("ben team2002 view error: %v", err)
	}
	if ben2002 != true {
		t.Fatalf("ben team2002 view got %v want true", ben2002)
	}
	ben1001, err := svc.HasTeamPermission(ctx, "ben", team1001, "", viewPerm.ID())
	if err != nil {
		t.Fatalf("ben team1001 view error: %v", err)
	}
	if ben1001 != false {
		t.Fatalf("ben team1001 view got %v want false", ben1001)
	}
	if got := exportPerm.Can(ctx, "chris", team1001); got != true {
		t.Fatalf("chris team1001 export got %v want true", got)
	}
	if got := exportPerm.Can(ctx, "chris", team2002); got != false {
		t.Fatalf("chris team2002 export got %v want false", got)
	}

	hits1001, err := svc.PrincipalsWithPermission(ctx, team1001, "", viewPerm.ID())
	if err != nil {
		t.Fatalf("hits1001: %v", err)
	}
	labels1001 := make([]string, 0, len(hits1001))
	for _, hit := range hits1001 {
		labels1001 = append(labels1001, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(labels1001)
	if len(labels1001) != 1 || labels1001[0] != "role:role.team_analyst_1001" {
		t.Fatalf("unexpected owners team1001: %v", labels1001)
	}

	hits2002, err := svc.PrincipalsWithPermission(ctx, team2002, "", viewPerm.ID())
	if err != nil {
		t.Fatalf("hits2002: %v", err)
	}
	labels2002 := make([]string, 0, len(hits2002))
	for _, hit := range hits2002 {
		labels2002 = append(labels2002, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(labels2002)
	if len(labels2002) != 1 || labels2002[0] != "role:role.team_analyst_2002" {
		t.Fatalf("unexpected owners team2002: %v", labels2002)
	}
}
