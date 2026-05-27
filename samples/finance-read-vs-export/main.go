package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
	"github.com/wtiger001/go-permissions/samples/shared"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	svc := permissions.NewService(store)

	readPerm := "finops.read"
	exportPerm := "finops.export"
	teamID := int64(900)
	teamScope := strconv.FormatInt(teamID, 10)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "analyst", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "manager", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "manager", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: exportPerm},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "intern", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "intern", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: exportPerm},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "intern", Effect: permissions.EffectDeny, TeamScope: teamScope, PermissionName: exportPerm},
	)

	for _, user := range []string{"analyst", "manager", "intern"} {
		shared.PrintTeamCheck(ctx, svc, user, teamID, readPerm, fmt.Sprintf("%s can read finops", user))
		shared.PrintTeamCheck(ctx, svc, user, teamID, exportPerm, fmt.Sprintf("%s can export finops", user))
	}
}
