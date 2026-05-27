package examples

import (
	"context"
	"sort"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestHierarchicalFolders verifies hierarchical object access and deny overrides for folder-reader role grants.
func TestHierarchicalFolders(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	perm := permissions.NewObjectPermission("folders.file.read", "Folders", "Read File", "Allows reading file contents for a specific hierarchical object path.").WithChecker(svc)

	workspaceID := "workspace-acme"
	financeFolderID := "folder-finance"
	engineeringFolderID := "folder-engineering"
	budgetFileID := "file-budget"
	payrollFileID := "file-payroll"
	roadmapFileID := "file-roadmap"
	budgetPath := budgetFileID + "/" + financeFolderID + "/" + workspaceID
	payrollPath := payrollFileID + "/" + financeFolderID + "/" + workspaceID

	if err := svc.AllowUser(ctx, "alice", perm.ID(), &budgetPath); err != nil {
		t.Fatalf("allow alice budget: %v", err)
	}
	if err := svc.AllowUser(ctx, "alice", perm.ID(), &payrollPath); err != nil {
		t.Fatalf("allow alice payroll: %v", err)
	}
	if err := svc.AllowRole(ctx, "role.finance_folder_reader", perm.ID(), &budgetPath); err != nil {
		t.Fatalf("allow role budget: %v", err)
	}
	if err := svc.AllowRole(ctx, "role.finance_folder_reader", perm.ID(), &payrollPath); err != nil {
		t.Fatalf("allow role payroll: %v", err)
	}
	if err := svc.AssignRoleToUser(ctx, "bob", "role.finance_folder_reader", nil); err != nil {
		t.Fatalf("assign role bob: %v", err)
	}
	if err := svc.DenyUser(ctx, "carol", perm.ID(), &budgetPath); err != nil {
		t.Fatalf("deny carol budget: %v", err)
	}
	store.AddGrants(permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.finance_folder_reader", Effect: permissions.EffectDeny, TeamScope: "*", ObjectScope: &payrollPath, PermissionName: perm.ID()})

	if got := perm.CanHierarchical(ctx, "alice", budgetFileID, financeFolderID, workspaceID); got != true {
		t.Fatalf("alice budget got %v want true", got)
	}
	if got := perm.CanHierarchical(ctx, "alice", payrollFileID, financeFolderID, workspaceID); got != true {
		t.Fatalf("alice payroll got %v want true", got)
	}
	if got := perm.CanHierarchical(ctx, "bob", budgetFileID, financeFolderID, workspaceID); got != true {
		t.Fatalf("bob budget got %v want true", got)
	}
	if got := perm.CanHierarchical(ctx, "bob", payrollFileID, financeFolderID, workspaceID); got != false {
		t.Fatalf("bob payroll got %v want false", got)
	}
	if got := perm.CanHierarchical(ctx, "carol", budgetFileID, financeFolderID, workspaceID); got != false {
		t.Fatalf("carol budget got %v want false", got)
	}
	if got := perm.CanHierarchical(ctx, "bob", roadmapFileID, engineeringFolderID, workspaceID); got != false {
		t.Fatalf("bob roadmap got %v want false", got)
	}

	budgetHits, err := svc.PrincipalsWithPermission(ctx, nil, budgetPath, perm.ID())
	if err != nil {
		t.Fatalf("budget hits: %v", err)
	}
	budgetLabels := make([]string, 0, len(budgetHits))
	for _, hit := range budgetHits {
		budgetLabels = append(budgetLabels, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(budgetLabels)
	if len(budgetLabels) != 2 || budgetLabels[0] != "role:role.finance_folder_reader" || budgetLabels[1] != "user:alice" {
		t.Fatalf("unexpected budget owners: %v", budgetLabels)
	}

	payrollHits, err := svc.PrincipalsWithPermission(ctx, nil, payrollPath, perm.ID())
	if err != nil {
		t.Fatalf("payroll hits: %v", err)
	}
	payrollLabels := make([]string, 0, len(payrollHits))
	for _, hit := range payrollHits {
		payrollLabels = append(payrollLabels, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(payrollLabels)
	if len(payrollLabels) != 1 || payrollLabels[0] != "user:alice" {
		t.Fatalf("unexpected payroll owners: %v", payrollLabels)
	}
}
