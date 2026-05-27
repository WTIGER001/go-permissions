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

	runPerm := permissions.NewTeamPermission("billing.jobs.run", "Billing", "Run Billing Jobs", "Allows running billing jobs.").WithChecker(svc)
	readPerm := permissions.NewTeamPermission("billing.jobs.read", "Billing", "Read Billing Jobs", "Allows reading billing jobs.").WithChecker(svc)

	team77 := int64(77)
	teamScope := strconv.FormatInt(team77, 10)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "svc-billing-sync", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: runPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "svc-billing-sync", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm.ID()},
	)

	okRun77 := runPerm.Can(ctx, "svc-billing-sync", 77)
	fmt.Printf("svc-billing-sync can run billing jobs on team 77: %t\n", okRun77)

	okRead77 := readPerm.Can(ctx, "svc-billing-sync", 77)
	fmt.Printf("svc-billing-sync can read billing jobs on team 77: %t\n", okRead77)

	okRun88 := runPerm.Can(ctx, "svc-billing-sync", 88)
	fmt.Printf("svc-billing-sync can run billing jobs on team 88: %t\n", okRun88)
}
