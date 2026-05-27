package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewServiceWithProviders(store, identity)

	systemFinopsPerm := permissions.NewSystemPermission(
		"finops.system.report.view",
		"FinOps",
		"View System Cost Report",
		"Allows viewing system-wide cost reporting.",
	).WithChecker(svc)

	teamFinopsPerm := permissions.NewTeamPermission(
		"finops.team.report.view",
		"FinOps",
		"View Team Cost Report",
		"Allows viewing team-level cost reporting.",
	).WithChecker(svc)

	registry := permissions.NewPermissionRegistry()
	registry.MustRegister(systemFinopsPerm.Definition())
	registry.MustRegister(teamFinopsPerm.Definition())

	fmt.Printf("registered permissions: %d\n", registry.Len())
	fmt.Println("users: alice, bob, carol, dave")
	fmt.Println("teams: 101, 202, 303")
	fmt.Println()

	// Direct grants
	if err := svc.AllowUser(ctx, "alice", systemFinopsPerm.ID(), nil); err != nil {
		panic(err)
	}
	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalUser,
		OwnerID:        "bob",
		Effect:         permissions.EffectAllow,
		TeamScope:      strconv.FormatInt(101, 10),
		PermissionName: teamFinopsPerm.ID(),
	})

	// Role-based grant and assignment
	if err := svc.AssignRoleToUser(ctx, "carol", "role.finops_team_reporter", nil); err != nil {
		panic(err)
	}
	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "role.finops_team_reporter",
		Effect:         permissions.EffectAllow,
		TeamScope:      strconv.FormatInt(202, 10),
		PermissionName: teamFinopsPerm.ID(),
	})

	fmt.Println("system-level checks")
	okAlice := systemFinopsPerm.Can(ctx, "alice")
	fmt.Printf("alice can view system-wide report: %t\n", okAlice)
	okBob := systemFinopsPerm.Can(ctx, "bob")
	fmt.Printf("bob can view system-wide report: %t\n", okBob)
	fmt.Println()

	fmt.Println("team-level checks")
	checks := []struct {
		user  string
		team  int64
		label string
	}{
		{"bob", 101, "bob can view team 101 report"},
		{"bob", 202, "bob can view team 202 report"},
		{"carol", 202, "carol can view team 202 report"},
		{"carol", 303, "carol can view team 303 report"},
		{"dave", 101, "dave can view team 101 report"},
	}
	for _, check := range checks {
		ok := teamFinopsPerm.Can(ctx, check.user, check.team)
		fmt.Printf("%s: %t\n", check.label, ok)
	}
	fmt.Println()

	fmt.Println("who has finops.system.report.view (grant owners)")
	systemHits, err := svc.PrincipalsWithPermission(ctx, nil, "", systemFinopsPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	printPrincipalHits(systemHits)
	fmt.Println()

	fmt.Println("who has finops.team.report.view for team 202 (grant owners)")
	teamID := int64(202)
	teamHits, err := svc.PrincipalsWithPermission(ctx, &teamID, "", teamFinopsPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	printPrincipalHits(teamHits)
}

func printPrincipalHits(hits []permissions.PrincipalHit) {
	labels := make([]string, 0, len(hits))
	for _, hit := range hits {
		labels = append(labels, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(labels)
	for _, label := range labels {
		fmt.Printf("- %s\n", label)
	}
}
