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

	fileReadPerm := permissions.NewObjectPermission(
		"folders.file.read",
		"Folders",
		"Read File",
		"Allows reading file contents for a specific hierarchical object path.",
	).WithChecker(svc)

	registry := permissions.NewPermissionRegistry()
	registry.MustRegister(fileReadPerm.Definition())

	workspaceID := "workspace-acme"
	financeFolderID := "folder-finance"
	engineeringFolderID := "folder-engineering"
	budgetFileID := "file-budget"
	payrollFileID := "file-payroll"
	roadmapFileID := "file-roadmap"

	budgetPath := budgetFileID + "/" + financeFolderID + "/" + workspaceID
	payrollPath := payrollFileID + "/" + financeFolderID + "/" + workspaceID
	roadmapPath := roadmapFileID + "/" + engineeringFolderID + "/" + workspaceID

	fmt.Printf("registered permissions: %d\n", registry.Len())
	fmt.Println("users: alice, bob, carol")
	fmt.Println("role: role.finance_folder_reader")
	fmt.Println("paths:")
	fmt.Printf("- budget: %s\n", budgetPath)
	fmt.Printf("- payroll: %s\n", payrollPath)
	fmt.Printf("- roadmap: %s\n", roadmapPath)
	fmt.Println()

	if err := svc.AllowUser(ctx, "alice", fileReadPerm.ID(), &budgetPath); err != nil {
		panic(err)
	}
	if err := svc.AllowUser(ctx, "alice", fileReadPerm.ID(), &payrollPath); err != nil {
		panic(err)
	}

	if err := svc.AllowRole(ctx, "role.finance_folder_reader", fileReadPerm.ID(), &budgetPath); err != nil {
		panic(err)
	}
	if err := svc.AllowRole(ctx, "role.finance_folder_reader", fileReadPerm.ID(), &payrollPath); err != nil {
		panic(err)
	}
	if err := svc.AssignRoleToUser(ctx, "bob", "role.finance_folder_reader", nil); err != nil {
		panic(err)
	}
	if err := svc.DenyUser(ctx, "carol", fileReadPerm.ID(), &budgetPath); err != nil {
		panic(err)
	}

	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "role.finance_folder_reader",
		Effect:         permissions.EffectDeny,
		TeamScope:      "*",
		ObjectScope:    &payrollPath,
		PermissionName: fileReadPerm.ID(),
	})

	fmt.Println("hierarchical checks")
	printHierarchicalCheck(ctx, fileReadPerm, "alice", budgetFileID, []string{financeFolderID, workspaceID}, "alice can read budget in finance")
	printHierarchicalCheck(ctx, fileReadPerm, "alice", payrollFileID, []string{financeFolderID, workspaceID}, "alice can read payroll in finance")
	printHierarchicalCheck(ctx, fileReadPerm, "bob", budgetFileID, []string{financeFolderID, workspaceID}, "bob can read budget in finance")
	printHierarchicalCheck(ctx, fileReadPerm, "bob", payrollFileID, []string{financeFolderID, workspaceID}, "bob can read payroll in finance")
	printHierarchicalCheck(ctx, fileReadPerm, "carol", budgetFileID, []string{financeFolderID, workspaceID}, "carol can read budget in finance")
	printHierarchicalCheck(ctx, fileReadPerm, "bob", roadmapFileID, []string{engineeringFolderID, workspaceID}, "bob can read roadmap in engineering")
	fmt.Println()

	fmt.Println("who has folders.file.read on budget path (grant owners)")
	budgetHits, err := svc.PrincipalsWithPermission(ctx, nil, budgetPath, fileReadPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	printPrincipalHits(budgetHits)
	fmt.Println()

	fmt.Println("who has folders.file.read on payroll path (grant owners)")
	payrollHits, err := svc.PrincipalsWithPermission(ctx, nil, payrollPath, fileReadPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	printPrincipalHits(payrollHits)
}

func printHierarchicalCheck(ctx context.Context, p *permissions.ObjectPermission, userID, leafID string, parentPath []string, label string) {
	ok := p.CanHierarchical(ctx, userID, leafID, parentPath...)
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
