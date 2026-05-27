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

	teamID := int64(808)
	teamScope := strconv.FormatInt(teamID, 10)
	user := "legacy-user"
	oldPerm := permissions.NewTeamPermission("reports.read", "Reports", "Read Reports", "Allows reading reports.").WithChecker(svc)
	newPerm := permissions.NewTeamPermission("reports.view", "Reports", "View Reports", "Allows viewing reports.").WithChecker(svc)

	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: user, Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: oldPerm.ID()})

	fmt.Println("before dual grant")
	okOldBefore := oldPerm.Can(ctx, user, teamID)
	fmt.Printf("legacy-user has reports.read: %t\n", okOldBefore)
	okNewBefore := newPerm.Can(ctx, user, teamID)
	fmt.Printf("legacy-user has reports.view: %t\n", okNewBefore)
	fmt.Println()

	fmt.Println("after dual grant")
	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: user, Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: newPerm.ID()})
	okOldAfter := oldPerm.Can(ctx, user, teamID)
	fmt.Printf("legacy-user has reports.read: %t\n", okOldAfter)
	okNewAfter := newPerm.Can(ctx, user, teamID)
	fmt.Printf("legacy-user has reports.view: %t\n", okNewAfter)
}
