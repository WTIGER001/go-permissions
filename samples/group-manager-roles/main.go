package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewServiceWithProviders(store, identity)

	createGroupPerm := permissions.NewSystemPermission(
		"groups.create",
		"Groups",
		"Create Group",
		"Allows creating groups in the system.",
	).WithChecker(svc)

	viewGroupNamePerm := permissions.NewSystemPermission(
		"groups.view.name",
		"Groups",
		"View Group Name",
		"Allows viewing group names.",
	).WithChecker(svc)

	manageMembersPerm := permissions.NewObjectPermission(
		"groups.members.manage",
		"Groups",
		"Manage Group Members",
		"Allows adding and removing members for a specific group.",
	).WithChecker(svc)

	registry := permissions.NewPermissionRegistry()
	registry.MustRegister(createGroupPerm.Definition())
	registry.MustRegister(viewGroupNamePerm.Definition())
	registry.MustRegister(manageMembersPerm.Definition())

	fmt.Printf("registered permissions: %d\n", registry.Len())
	fmt.Println("users: user1, user2, user3, user4")
	fmt.Println("groups: group1, group2, group3, group4")
	fmt.Println()

	fmt.Println("phase 1: system-level permissions")
	if err := svc.AllowUser(ctx, "user1", createGroupPerm.ID(), nil); err != nil {
		panic(err)
	}
	if err := svc.AllowUser(ctx, "user1", viewGroupNamePerm.ID(), nil); err != nil {
		panic(err)
	}
	if err := svc.AllowUser(ctx, "user2", viewGroupNamePerm.ID(), nil); err != nil {
		panic(err)
	}

	checkSystem(ctx, createGroupPerm, "user1", "user1 can create groups")
	checkSystem(ctx, createGroupPerm, "user2", "user2 can create groups")
	checkSystem(ctx, viewGroupNamePerm, "user2", "user2 can view group names")
	fmt.Println()

	fmt.Println("phase 2: group-scoped management permission")
	newGroupID := "group5"
	if err := svc.AllowUser(ctx, "user1", manageMembersPerm.ID(), &newGroupID); err != nil {
		panic(err)
	}

	checkObject(ctx, manageMembersPerm, "user1", "group5", "user1 can manage members for group5")
	checkObject(ctx, manageMembersPerm, "user1", "group2", "user1 can manage members for group2")
	fmt.Println()

	fmt.Println("phase 3: group manager role")
	if err := svc.AssignRoleToUser(ctx, "user3", "role.group_manager", nil); err != nil {
		panic(err)
	}
	if err := svc.AssignRoleToUser(ctx, "user4", "role.group_manager", nil); err != nil {
		panic(err)
	}
	if err := svc.AllowRole(ctx, "role.group_manager", manageMembersPerm.ID(), &newGroupID); err != nil {
		panic(err)
	}

	checkObject(ctx, manageMembersPerm, "user3", "group5", "user3 can manage members for group5")
	checkObject(ctx, manageMembersPerm, "user4", "group5", "user4 can manage members for group5")
	checkObject(ctx, manageMembersPerm, "user2", "group5", "user2 can manage members for group5")
	fmt.Println()

	fmt.Println("who has groups.members.manage on group5 (grant owners)")
	hits, err := svc.PrincipalsWithPermission(ctx, nil, "group5", manageMembersPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	printPrincipalHits(hits)
}

func checkSystem(ctx context.Context, perm *permissions.SystemPermission, userID, label string) {
	ok := perm.Can(ctx, userID)
	fmt.Printf("%s: %t\n", label, ok)
}

func checkObject(ctx context.Context, perm *permissions.ObjectPermission, userID, objectID, label string) {
	ok := perm.Can(ctx, userID, objectID)
	fmt.Printf("%s: %t\n", label, ok)
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
