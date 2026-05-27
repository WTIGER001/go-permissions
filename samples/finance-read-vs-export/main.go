package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewServiceWithProviders(store, identity)

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

	for _, user := range []string{"analyst", "manager", "intern"} {
		labelRead := fmt.Sprintf("%s can read finops", user)
		okRead := readPerm.Can(ctx, user, teamID)
		fmt.Printf("%s: %t\n", labelRead, okRead)

		labelExport := fmt.Sprintf("%s can export finops", user)
		okExport := exportPerm.Can(ctx, user, teamID)
		fmt.Printf("%s: %t\n", labelExport, okExport)
	}
}
