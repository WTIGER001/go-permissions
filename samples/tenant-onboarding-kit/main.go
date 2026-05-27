package main

import (
	"context"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
	"github.com/wtiger001/go-permissions/samples/shared"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	svc := permissions.NewService(store)

	team555 := int64(555)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.tenant_starter", Effect: permissions.EffectAllow, TeamScope: "?team", PermissionName: "projects.view", VariableSpec: map[string]any{"team": "required"}},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.tenant_starter", Effect: permissions.EffectAllow, TeamScope: "?team", PermissionName: "projects.create", VariableSpec: map[string]any{"team": "required"}},
	)

	shared.Must(svc.AssignRoleToUser(ctx, "tenant-admin", "role.tenant_starter", map[string]any{"team": team555}))

	shared.PrintTeamCheck(ctx, svc, "tenant-admin", 555, "projects.view", "tenant-admin can view projects on team 555")
	shared.PrintTeamCheck(ctx, svc, "tenant-admin", 555, "projects.create", "tenant-admin can create projects on team 555")
	shared.PrintTeamCheck(ctx, svc, "tenant-admin", 777, "projects.view", "tenant-admin can view projects on team 777")
}
