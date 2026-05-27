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

	teamID := int64(3003)
	teamScope := strconv.FormatInt(teamID, 10)

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "auditor-1", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.invoice.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "finance-reviewers", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: "billing.invoice.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectAllow, TeamScope: teamScope, ObjectScope: shared.StrPtr("invoice-123"), PermissionName: "billing.invoice.approve"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectAllow, TeamScope: teamScope, ObjectScope: shared.StrPtr("invoice-locked"), PermissionName: "billing.invoice.approve"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "role.approver", Effect: permissions.EffectDeny, TeamScope: teamScope, ObjectScope: shared.StrPtr("invoice-locked"), PermissionName: "billing.invoice.approve"},
	)

	fmt.Println("who has billing.invoice.read")
	hitsRead, _ := svc.PrincipalsWithPermission(ctx, &teamID, "", "billing.invoice.read")
	shared.PrintPrincipalHits(hitsRead)
	fmt.Println()

	fmt.Println("who has billing.invoice.approve on invoice-123")
	hitsApprove, _ := svc.PrincipalsWithPermission(ctx, &teamID, "invoice-123", "billing.invoice.approve")
	shared.PrintPrincipalHits(hitsApprove)
	fmt.Println()

	fmt.Println("who has billing.invoice.approve on invoice-locked")
	hitsLocked, _ := svc.PrincipalsWithPermission(ctx, &teamID, "invoice-locked", "billing.invoice.approve")
	shared.PrintPrincipalHits(hitsLocked)
}
