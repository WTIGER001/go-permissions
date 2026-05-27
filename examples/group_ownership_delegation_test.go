package examples

import (
	"context"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestGroupOwnershipDelegation verifies delegated management is scoped only to owned groups.
func TestGroupOwnershipDelegation(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	perm := permissions.NewObjectPermission("groups.members.manage", "Groups", "Manage Members", "Allows managing members for one group.").WithChecker(svc)
	groupA := "group-a"
	if err := svc.AllowUser(ctx, "lead-1", perm.ID(), &groupA); err != nil {
		t.Fatalf("allow lead-1 on group-a: %v", err)
	}

	if got := perm.Can(ctx, "lead-1", "group-a"); got != true {
		t.Fatalf("group-a got %v want true", got)
	}
	if got := perm.Can(ctx, "lead-1", "group-b"); got != false {
		t.Fatalf("group-b got %v want false", got)
	}
}
