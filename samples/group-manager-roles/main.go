package main

import (
	"context"
	"fmt"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
	"github.com/wtiger001/go-permissions/samples/shared"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	svc := permissions.NewService(store)

	createGroupPerm := permissions.NewSystemPermission(
		"groups.create",
		"Groups",
		"Create Group",
		"Allows creating groups in the system.",
		true,
	).WithChecker(svc)

	viewGroupNamePerm := permissions.NewSystemPermission(
		"groups.view.name",
		"Groups",
		"View Group Name",
		"Allows viewing group names.",
		true,
	).WithChecker(svc)

	manageMembersPerm := permissions.NewObjectPermission(
		"groups.members.manage",
		"Groups",
		"Manage Group Members",
		"Allows adding and removing members for a specific group.",
		true,
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
	shared.Must(svc.AllowUser(ctx, "user1", createGroupPerm.ID(), nil))
	shared.Must(svc.AllowUser(ctx, "user1", viewGroupNamePerm.ID(), nil))
	shared.Must(svc.AllowUser(ctx, "user2", viewGroupNamePerm.ID(), nil))

	shared.PrintSystemCheck(ctx, svc, "user1", createGroupPerm.ID(), "user1 can create groups")
	shared.PrintSystemCheck(ctx, svc, "user2", createGroupPerm.ID(), "user2 can create groups")
	shared.PrintSystemCheck(ctx, svc, "user2", viewGroupNamePerm.ID(), "user2 can view group names")
	fmt.Println()

	fmt.Println("phase 2: group-scoped management permission")
	newGroupID := "group5"
	shared.Must(svc.AllowUser(ctx, "user1", manageMembersPerm.ID(), shared.StrPtr(newGroupID)))

	shared.PrintObjectCheck(ctx, svc, "user1", "group5", manageMembersPerm.ID(), "user1 can manage members for group5")
	shared.PrintObjectCheck(ctx, svc, "user1", "group2", manageMembersPerm.ID(), "user1 can manage members for group2")
	fmt.Println()

	fmt.Println("phase 3: group manager role")
	shared.Must(svc.AssignRoleToUser(ctx, "user3", "role.group_manager", nil))
	shared.Must(svc.AssignRoleToUser(ctx, "user4", "role.group_manager", nil))
	shared.Must(svc.AllowRole(ctx, "role.group_manager", manageMembersPerm.ID(), shared.StrPtr(newGroupID)))

	shared.PrintObjectCheck(ctx, svc, "user3", "group5", manageMembersPerm.ID(), "user3 can manage members for group5")
	shared.PrintObjectCheck(ctx, svc, "user4", "group5", manageMembersPerm.ID(), "user4 can manage members for group5")
	shared.PrintObjectCheck(ctx, svc, "user2", "group5", manageMembersPerm.ID(), "user2 can manage members for group5")
	fmt.Println()

	fmt.Println("who has groups.members.manage on group5 (grant owners)")
	hits, err := svc.PrincipalsWithPermission(ctx, nil, "group5", manageMembersPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	shared.PrintPrincipalHits(hits)
}
