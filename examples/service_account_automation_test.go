package examples

import (
	"context"
	"strconv"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestServiceAccountAutomation verifies a service account has narrow team-scoped automation grants.
func TestServiceAccountAutomation(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	runPerm := permissions.NewTeamPermission("billing.jobs.run", "Billing", "Run Billing Jobs", "Allows running billing jobs.").WithChecker(svc)
	readPerm := permissions.NewTeamPermission("billing.jobs.read", "Billing", "Read Billing Jobs", "Allows reading billing jobs.").WithChecker(svc)

	team77 := int64(77)
	teamScope := strconv.FormatInt(team77, 10)
	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "svc-billing-sync", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: runPerm.ID()},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "svc-billing-sync", Effect: permissions.EffectAllow, TeamScope: teamScope, PermissionName: readPerm.ID()},
	)

	if got := runPerm.Can(ctx, "svc-billing-sync", 77); got != true {
		t.Fatalf("run team 77 got %v want true", got)
	}
	if got := readPerm.Can(ctx, "svc-billing-sync", 77); got != true {
		t.Fatalf("read team 77 got %v want true", got)
	}
	if got := runPerm.Can(ctx, "svc-billing-sync", 88); got != false {
		t.Fatalf("run team 88 got %v want false", got)
	}
}
