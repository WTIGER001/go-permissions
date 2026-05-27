package main

import (
	"context"
	"fmt"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewServiceWithProviders(store, identity)

	projectsViewPerm := permissions.NewTeamPermission("projects.view", "Projects", "View Projects", "Allows viewing projects for a team.").WithChecker(svc)
	projectsCreatePerm := permissions.NewTeamPermission("projects.create", "Projects", "Create Projects", "Allows creating projects for a team.").WithChecker(svc)

	team555 := int64(555)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.tenant_starter", Effect: permissions.EffectAllow, TeamScope: "?team", PermissionName: "projects.view", VariableSpec: map[string]any{"team": "required"}},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.tenant_starter", Effect: permissions.EffectAllow, TeamScope: "?team", PermissionName: "projects.create", VariableSpec: map[string]any{"team": "required"}},
	)

	if err := svc.AssignRoleToUser(ctx, "tenant-admin", "role.tenant_starter", map[string]any{"team": team555}); err != nil {
		panic(err)
	}

	checks := []struct {
		team int64
		perm *permissions.TeamPermission
		msg  string
	}{
		{555, projectsViewPerm, "tenant-admin can view projects on team 555"},
		{555, projectsCreatePerm, "tenant-admin can create projects on team 555"},
		{777, projectsViewPerm, "tenant-admin can view projects on team 777"},
	}
	for _, check := range checks {
		ok := check.perm.Can(ctx, "tenant-admin", check.team)
		fmt.Printf("%s: %t\n", check.msg, ok)
	}
}
