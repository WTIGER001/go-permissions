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

	teamID := int64(3003)
	teamScope := strconv.FormatInt(teamID, 10)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "auditor-1", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.invoice.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "finance-reviewers", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.invoice.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectAllow, TeamScope: teamScope, ObjectScope: strPtr("invoice-123"), PermissionName: "billing.invoice.approve"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectAllow, TeamScope: teamScope, ObjectScope: strPtr("invoice-locked"), PermissionName: "billing.invoice.approve"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectDeny, TeamScope: teamScope, ObjectScope: strPtr("invoice-locked"), PermissionName: "billing.invoice.approve"},
	)

	fmt.Println("who has billing.invoice.read")
	hitsRead, _ := svc.PrincipalsWithPermission(ctx, &teamID, "", "billing.invoice.read")
	printPrincipalHits(hitsRead)
	fmt.Println()

	fmt.Println("who has billing.invoice.approve on invoice-123")
	hitsApprove, _ := svc.PrincipalsWithPermission(ctx, &teamID, "invoice-123", "billing.invoice.approve")
	printPrincipalHits(hitsApprove)
	fmt.Println()

	fmt.Println("who has billing.invoice.approve on invoice-locked")
	hitsLocked, _ := svc.PrincipalsWithPermission(ctx, &teamID, "invoice-locked", "billing.invoice.approve")
	printPrincipalHits(hitsLocked)
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

func strPtr(v string) *string {
	return &v
}
