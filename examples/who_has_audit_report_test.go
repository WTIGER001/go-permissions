package examples

import (
	"context"
	"sort"
		"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestWhoHasAuditReport verifies principal ownership reports across team and object scope with deny suppression.
func TestWhoHasAuditReport(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	teamID := "3003"
	teamScope := teamID
	invoice123 := "invoice-123"
	invoiceLocked := "invoice-locked"
	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "auditor-1", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.invoice.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "finance-reviewers", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.invoice.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectAllow, TeamScope: teamScope, ObjectScope: &invoice123, PermissionName: "billing.invoice.approve"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectAllow, TeamScope: teamScope, ObjectScope: &invoiceLocked, PermissionName: "billing.invoice.approve"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectDeny, TeamScope: teamScope, ObjectScope: &invoiceLocked, PermissionName: "billing.invoice.approve"},
	)

	hitsRead, err := svc.PrincipalsWithPermission(ctx, teamID, "", "billing.invoice.read")
	if err != nil {
		t.Fatalf("read hits: %v", err)
	}
	labelsRead := make([]string, 0, len(hitsRead))
	for _, hit := range hitsRead {
		labelsRead = append(labelsRead, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(labelsRead)
	if len(labelsRead) != 2 || labelsRead[0] != "group:finance-reviewers" || labelsRead[1] != "user:auditor-1" {
		t.Fatalf("unexpected read owners: %v", labelsRead)
	}

	hitsApprove, err := svc.PrincipalsWithPermission(ctx, teamID, "invoice-123", "billing.invoice.approve")
	if err != nil {
		t.Fatalf("approve hits invoice-123: %v", err)
	}
	labelsApprove := make([]string, 0, len(hitsApprove))
	for _, hit := range hitsApprove {
		labelsApprove = append(labelsApprove, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(labelsApprove)
	if len(labelsApprove) != 1 || labelsApprove[0] != "role:role.approver" {
		t.Fatalf("unexpected approve owners invoice-123: %v", labelsApprove)
	}

	hitsLocked, err := svc.PrincipalsWithPermission(ctx, teamID, "invoice-locked", "billing.invoice.approve")
	if err != nil {
		t.Fatalf("approve hits invoice-locked: %v", err)
	}
	if len(hitsLocked) != 0 {
		t.Fatalf("expected no owners invoice-locked, got %v", hitsLocked)
	}
}
