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

	teamID := int64(808)
	teamScope := strconv.FormatInt(teamID, 10)
	user := "legacy-user"
	oldPerm := "reports.read"
	newPerm := "reports.view"

	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: user, Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: oldPerm})

	fmt.Println("before dual grant")
	shared.PrintTeamCheck(ctx, svc, user, teamID, oldPerm, "legacy-user has reports.read")
	shared.PrintTeamCheck(ctx, svc, user, teamID, newPerm, "legacy-user has reports.view")
	fmt.Println()

	fmt.Println("after dual grant")
	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: user, Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: newPerm})
	shared.PrintTeamCheck(ctx, svc, user, teamID, oldPerm, "legacy-user has reports.read")
	shared.PrintTeamCheck(ctx, svc, user, teamID, newPerm, "legacy-user has reports.view")
}
