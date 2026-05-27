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

	fileReadPerm := permissions.NewObjectPermission(
		"folders.file.read",
		"Folders",
		"Read File",
		"Allows reading file contents for a specific hierarchical object path.",
		true,
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

	shared.Must(svc.AllowUser(ctx, "alice", fileReadPerm.ID(), shared.StrPtr(budgetPath)))
	shared.Must(svc.AllowUser(ctx, "alice", fileReadPerm.ID(), shared.StrPtr(payrollPath)))

	shared.Must(svc.AllowRole(ctx, "role.finance_folder_reader", fileReadPerm.ID(), shared.StrPtr(budgetPath)))
	shared.Must(svc.AllowRole(ctx, "role.finance_folder_reader", fileReadPerm.ID(), shared.StrPtr(payrollPath)))
	shared.Must(svc.AssignRoleToUser(ctx, "bob", "role.finance_folder_reader", nil))
	shared.Must(svc.DenyUser(ctx, "carol", fileReadPerm.ID(), shared.StrPtr(budgetPath)))

	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "role.finance_folder_reader",
		Effect:         permissions.EffectDeny,
		TeamScope:      "*",
		ObjectScope:    shared.StrPtr(payrollPath),
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
	shared.PrintPrincipalHits(budgetHits)
	fmt.Println()

	fmt.Println("who has folders.file.read on payroll path (grant owners)")
	payrollHits, err := svc.PrincipalsWithPermission(ctx, nil, payrollPath, fileReadPerm.ID())
	if err != nil {
		fmt.Printf("query error: %v\n", err)
		return
	}
	shared.PrintPrincipalHits(payrollHits)
}

func printHierarchicalCheck(ctx context.Context, p *permissions.ObjectPermission, userID, leafID string, parentPath []string, label string) {
	ok, err := p.CanHierarchical(ctx, userID, leafID, parentPath...)
	if err != nil {
		fmt.Printf("%s: error=%v\n", label, err)
		return
	}
	fmt.Printf("%s: %t\n", label, ok)
}
