package examples

import (
	"context"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestRegionalComplianceFence verifies a broad allow with an object-level deny compliance fence.
func TestRegionalComplianceFence(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	perm := permissions.NewObjectPermission("datasets.view", "Data", "View Dataset", "Allows viewing datasets by region.").WithChecker(svc)

	if err := svc.AllowUser(ctx, "analyst-global", perm.ID(), nil); err != nil {
		t.Fatalf("allow analyst-global: %v", err)
	}
	restricted := "region-restricted"
	if err := svc.DenyUser(ctx, "analyst-global", perm.ID(), &restricted); err != nil {
		t.Fatalf("deny analyst-global restricted: %v", err)
	}

	if got := perm.Can(ctx, "analyst-global", "region-us"); got != true {
		t.Fatalf("region-us got %v want true", got)
	}
	if got := perm.Can(ctx, "analyst-global", "region-eu"); got != true {
		t.Fatalf("region-eu got %v want true", got)
	}
	if got := perm.Can(ctx, "analyst-global", "region-restricted"); got != false {
		t.Fatalf("region-restricted got %v want false", got)
	}
}
