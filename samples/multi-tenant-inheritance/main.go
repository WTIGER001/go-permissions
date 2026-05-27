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

	reportsViewPerm := permissions.NewTeamPermission(
		"reports.view",
		"Reports",
		"View Team Reports",
		"Allows viewing reports for a team.",
		true,
	).WithChecker(svc)

	reportsExportPerm := permissions.NewTeamPermission(
		"reports.export",
		"Reports",
		"Export Team Reports",
		"Allows exporting reports for a team.",
		true,
	).WithChecker(svc)

	registry := permissions.NewPermissionRegistry()
	registry.MustRegister(reportsViewPerm.Definition())
	registry.MustRegister(reportsExportPerm.Definition())

	team1001 := int64(1001)
	team2002 := int64(2002)

	fmt.Printf("registered permissions: %d\n", registry.Len())
	fmt.Println("users: anna, ben, chris")
	fmt.Println("teams: 1001, 2002")
	fmt.Println("roles: role.viewer, role.team_analyst")
	fmt.Println()

	// Role inheritance: assigning role.team_analyst expands to role.viewer.
	store.SetRoleExpansion("role.team_analyst", "role.viewer")

	// Template-bound inherited grant on role.viewer.
	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "role.viewer",
		Effect:         permissions.EffectAllow,
		TeamScope:      "?team",
		PermissionName: reportsViewPerm.ID(),
		VariableSpec: map[string]any{
			"team": "required",
		},
	})

	// Assign same role with different team bindings.
	shared.Must(svc.AssignRoleToUser(ctx, "anna", "role.team_analyst", map[string]any{"team": team1001}))
	shared.Must(svc.AssignRoleToUser(ctx, "ben", "role.team_analyst", map[string]any{"team": team2002}))

	// Direct team-scoped export for chris on team 1001.
	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalUser,
		OwnerID:        "chris",
		Effect:         permissions.EffectAllow,
		TeamScope:      strconv.FormatInt(team1001, 10),
		PermissionName: reportsExportPerm.ID(),
	})

	fmt.Println("team checks")
	shared.PrintTeamCheck(ctx, svc, "anna", team1001, reportsViewPerm.ID(), "anna can view reports for team 1001")
	shared.PrintTeamCheck(ctx, svc, "anna", team2002, reportsViewPerm.ID(), "anna can view reports for team 2002")
	shared.PrintTeamCheck(ctx, svc, "ben", team2002, reportsViewPerm.ID(), "ben can view reports for team 2002")
	shared.PrintTeamCheck(ctx, svc, "ben", team1001, reportsViewPerm.ID(), "ben can view reports for team 1001")
	shared.PrintTeamCheck(ctx, svc, "chris", team1001, reportsExportPerm.ID(), "chris can export reports for team 1001")
	shared.PrintTeamCheck(ctx, svc, "chris", team2002, reportsExportPerm.ID(), "chris can export reports for team 2002")
	fmt.Println()

	fmt.Println("who has reports.view for team 1001 (grant owners)")
	hits1001, err := svc.PrincipalsWithPermission(ctx, &team1001, "", reportsViewPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	shared.PrintPrincipalHits(hits1001)
	fmt.Println()

	fmt.Println("who has reports.view for team 2002 (grant owners)")
	hits2002, err := svc.PrincipalsWithPermission(ctx, &team2002, "", reportsViewPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	shared.PrintPrincipalHits(hits2002)
}
