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

	perm := permissions.NewTeamPermission("tasks.view", "Tasks", "View Tasks", "Allows viewing tasks for a team.", true).WithChecker(svc)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "contractor-1", Effect: permissions.EffectAllow, TeamScope: strconv.FormatInt(11, 10), PermissionName: perm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "contractor-1", Effect: permissions.EffectAllow, TeamScope: strconv.FormatInt(33, 10), PermissionName: perm.ID()},
	)

	for _, team := range []int64{11, 22, 33, 44} {
		label := fmt.Sprintf("contractor-1 can view tasks for team %d", team)
		shared.PrintTeamCheck(ctx, svc, "contractor-1", team, perm.ID(), label)
	}
}
