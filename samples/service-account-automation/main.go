package main

import (
	"context"
	"strconv"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
	"github.com/wtiger001/go-permissions/samples/shared"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	svc := permissions.NewService(store)

	team77 := int64(77)
	teamScope := strconv.FormatInt(team77, 10)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "svc-billing-sync", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.jobs.run"},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "svc-billing-sync", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.jobs.read"},
	)

	shared.PrintTeamCheck(ctx, svc, "svc-billing-sync", 77, "billing.jobs.run", "svc-billing-sync can run billing jobs on team 77")
	shared.PrintTeamCheck(ctx, svc, "svc-billing-sync", 77, "billing.jobs.read", "svc-billing-sync can read billing jobs on team 77")
	shared.PrintTeamCheck(ctx, svc, "svc-billing-sync", 88, "billing.jobs.run", "svc-billing-sync can run billing jobs on team 88")
}
