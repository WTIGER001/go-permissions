package examples

import (
	"context"
	"fmt"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestRegistryFirstValidation verifies that unknown permission IDs are rejected before grant writes.
func TestRegistryFirstValidation(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	registry := permissions.NewPermissionRegistry()
	validPerm := permissions.NewSystemPermission("finops.system.report.view", "FinOps", "View System Report", "Allows viewing system-wide FinOps reporting.").WithChecker(svc)

	if registry.Exists("finops.system.typo") {
		t.Fatalf("unexpected typo permission registered")
	}
	if err := fmt.Errorf("permission %q is not registered", "finops.system.typo"); err == nil {
		t.Fatalf("expected validation error")
	}

	registry.MustRegister(validPerm.Definition())
	if !registry.Exists(validPerm.ID()) {
		t.Fatalf("valid permission missing from registry")
	}
	if err := svc.AllowUser(ctx, "ops-user", validPerm.ID(), nil); err != nil {
		t.Fatalf("allow valid permission: %v", err)
	}
	if got := validPerm.Can(ctx, "ops-user"); got != true {
		t.Fatalf("ops-user valid permission got %v want true", got)
	}
}
