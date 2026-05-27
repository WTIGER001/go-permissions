package examples

import (
	"context"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestBreakGlassAdmin verifies emergency role access with an explicit object-level deny guardrail.
func TestBreakGlassAdmin(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	perm := permissions.NewObjectPermission("incidents.resolve", "Incidents", "Resolve Incident", "Allows resolving incidents.").WithChecker(svc)

	if err := svc.AllowRole(ctx, "role.break_glass", perm.ID(), nil); err != nil {
		t.Fatalf("allow role: %v", err)
	}
	if err := svc.AssignRoleToUser(ctx, "oncall-admin", "role.break_glass", nil); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	incident42 := "incident-42"
	if err := svc.DenyUser(ctx, "oncall-admin", perm.ID(), &incident42); err != nil {
		t.Fatalf("deny user: %v", err)
	}

	if got := perm.Can(ctx, "oncall-admin", "incident-41"); got != true {
		t.Fatalf("incident-41 got %v want true", got)
	}
	if got := perm.Can(ctx, "oncall-admin", "incident-42"); got != false {
		t.Fatalf("incident-42 got %v want false", got)
	}
}
