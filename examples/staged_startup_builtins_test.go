package examples

import (
	"context"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestStagedStartupBuiltIns verifies staged service wiring and built-in seeding on SetStore.
func TestStagedStartupBuiltIns(t *testing.T) {
	ctx := context.Background()

	svc := permissions.New()
	svc.SetIdentityProvider(inmemory.NewIdentityProvider())
	svc.SetSyntheticRoleIDs(
		permissions.SyntheticRolePublic,
		permissions.SyntheticRoleAuthenticated,
		permissions.SyntheticRoleAdmin,
	)
	svc.SetBuiltInGrants([]permissions.Grant{
		{
			OwnerKind:      permissions.PrincipalRole,
			OwnerID:        permissions.SyntheticRolePublic,
			Effect:         permissions.EffectAllow,
			TeamScope:      "*",
			PermissionName: "assets.read",
		},
	})

	if err := svc.SetStore(inmemory.NewStore()); err != nil {
		t.Fatalf("set store bootstrap failed: %v", err)
	}

	allowed, err := svc.HasPermission(ctx, permissions.Request{Perm: "assets.read"})
	if err != nil {
		t.Fatalf("public check error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected public built-in grant to allow assets.read")
	}
}
