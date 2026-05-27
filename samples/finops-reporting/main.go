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

	systemFinopsPerm := permissions.NewSystemPermission(
		"finops.system.report.view",
		"FinOps",
		"View System Cost Report",
		"Allows viewing system-wide cost reporting.",
		true,
	).WithChecker(svc)

	teamFinopsPerm := permissions.NewTeamPermission(
		"finops.team.report.view",
		"FinOps",
		"View Team Cost Report",
		"Allows viewing team-level cost reporting.",
		true,
	).WithChecker(svc)

	registry := permissions.NewPermissionRegistry()
	registry.MustRegister(systemFinopsPerm.Definition())
	registry.MustRegister(teamFinopsPerm.Definition())

	fmt.Printf("registered permissions: %d\n", registry.Len())
	fmt.Println("users: alice, bob, carol, dave")
	fmt.Println("teams: 101, 202, 303")
	fmt.Println()

	// Direct grants
	shared.Must(svc.AllowUser(ctx, "alice", systemFinopsPerm.ID(), nil))
	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalUser,
		OwnerID:        "bob",
		Effect:         permissions.EffectAllow,
		TeamScope:      strconv.FormatInt(101, 10),
		PermissionName: teamFinopsPerm.ID(),
	})

	// Role-based grant and assignment
	shared.Must(svc.AssignRoleToUser(ctx, "carol", "role.finops_team_reporter", nil))
	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "role.finops_team_reporter",
		Effect:         permissions.EffectAllow,
		TeamScope:      strconv.FormatInt(202, 10),
		PermissionName: teamFinopsPerm.ID(),
	})

	fmt.Println("system-level checks")
	shared.PrintSystemCheck(ctx, svc, "alice", systemFinopsPerm.ID(), "alice can view system-wide report")
	shared.PrintSystemCheck(ctx, svc, "bob", systemFinopsPerm.ID(), "bob can view system-wide report")
	fmt.Println()

	fmt.Println("team-level checks")
	shared.PrintTeamCheck(ctx, svc, "bob", 101, teamFinopsPerm.ID(), "bob can view team 101 report")
	shared.PrintTeamCheck(ctx, svc, "bob", 202, teamFinopsPerm.ID(), "bob can view team 202 report")
	shared.PrintTeamCheck(ctx, svc, "carol", 202, teamFinopsPerm.ID(), "carol can view team 202 report")
	shared.PrintTeamCheck(ctx, svc, "carol", 303, teamFinopsPerm.ID(), "carol can view team 303 report")
	shared.PrintTeamCheck(ctx, svc, "dave", 101, teamFinopsPerm.ID(), "dave can view team 101 report")
	fmt.Println()

	fmt.Println("who has finops.system.report.view (grant owners)")
	systemHits, err := svc.PrincipalsWithPermission(ctx, nil, "", systemFinopsPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	shared.PrintPrincipalHits(systemHits)
	fmt.Println()

	fmt.Println("who has finops.team.report.view for team 202 (grant owners)")
	teamID := int64(202)
	teamHits, err := svc.PrincipalsWithPermission(ctx, &teamID, "", teamFinopsPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	shared.PrintPrincipalHits(teamHits)
}
