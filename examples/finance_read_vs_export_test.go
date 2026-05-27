package examples

import (
	"context"
	"strconv"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestFinanceReadVsExport verifies broad read access with tighter export controls and deny precedence.
func TestFinanceReadVsExport(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	readPerm := permissions.NewTeamPermission("finops.read", "FinOps", "Read FinOps", "Allows reading FinOps data for a team.").WithChecker(svc)
	exportPerm := permissions.NewTeamPermission("finops.export", "FinOps", "Export FinOps", "Allows exporting FinOps data for a team.").WithChecker(svc)
	teamID := int64(900)
	teamScope := strconv.FormatInt(teamID, 10)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "analyst", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "manager", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "manager", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: exportPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "intern", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "intern", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: exportPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "intern", Effect: permissions.EffectDeny, TeamScope: teamScope, PermissionName: exportPerm.ID()},
	)

	if got := readPerm.Can(ctx, "analyst", teamID); got != true {
		t.Fatalf("analyst read got %v want true", got)
	}
	if got := exportPerm.Can(ctx, "analyst", teamID); got != false {
		t.Fatalf("analyst export got %v want false", got)
	}
	if got := readPerm.Can(ctx, "manager", teamID); got != true {
		t.Fatalf("manager read got %v want true", got)
	}
	if got := exportPerm.Can(ctx, "manager", teamID); got != true {
		t.Fatalf("manager export got %v want true", got)
	}
	if got := readPerm.Can(ctx, "intern", teamID); got != true {
		t.Fatalf("intern read got %v want true", got)
	}
	if got := exportPerm.Can(ctx, "intern", teamID); got != false {
		t.Fatalf("intern export got %v want false", got)
	}
}
