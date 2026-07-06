package examples

import (
	"context"
	"sort"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

// TestGroupManagerRoles verifies system and object permissions as role-based ownership grows over phases.
func TestGroupManagerRoles(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	createPerm := permissions.NewSystemPermission("groups.create", "Groups", "Create Group", "Allows creating groups in the system.").WithChecker(svc)
	viewNamePerm := permissions.NewSystemPermission("groups.view.name", "Groups", "View Group Name", "Allows viewing group names.").WithChecker(svc)
	managePerm := permissions.NewObjectPermission("groups.members.manage", "Groups", "Manage Group Members", "Allows adding and removing members for a specific group.").WithChecker(svc)

	if err := svc.AllowUser(ctx, "user1", createPerm.ID(), nil); err != nil {
		t.Fatalf("allow user1 create: %v", err)
	}
	if err := svc.AllowUser(ctx, "user1", viewNamePerm.ID(), nil); err != nil {
		t.Fatalf("allow user1 view name: %v", err)
	}
	if err := svc.AllowUser(ctx, "user2", viewNamePerm.ID(), nil); err != nil {
		t.Fatalf("allow user2 view name: %v", err)
	}

	if got := createPerm.Can(ctx, "user1"); got != true {
		t.Fatalf("user1 create got %v want true", got)
	}
	if got := createPerm.Can(ctx, "user2"); got != false {
		t.Fatalf("user2 create got %v want false", got)
	}
	if got := viewNamePerm.Can(ctx, "user2"); got != true {
		t.Fatalf("user2 view names got %v want true", got)
	}

	group5 := "group5"
	if err := svc.AllowUser(ctx, "user1", managePerm.ID(), &group5); err != nil {
		t.Fatalf("allow user1 manage group5: %v", err)
	}
	if got := managePerm.Can(ctx, "user1", "group5"); got != true {
		t.Fatalf("user1 group5 manage got %v want true", got)
	}
	if got := managePerm.Can(ctx, "user1", "group2"); got != false {
		t.Fatalf("user1 group2 manage got %v want false", got)
	}

	if err := svc.AssignRoleToUser(ctx, "user3", "role.group_manager", nil); err != nil {
		t.Fatalf("assign user3 role: %v", err)
	}
	if err := svc.AssignRoleToUser(ctx, "user4", "role.group_manager", nil); err != nil {
		t.Fatalf("assign user4 role: %v", err)
	}
	if err := svc.AllowRole(ctx, "role.group_manager", managePerm.ID(), &group5); err != nil {
		t.Fatalf("allow role group_manager group5: %v", err)
	}

	if got := managePerm.Can(ctx, "user3", "group5"); got != true {
		t.Fatalf("user3 group5 manage got %v want true", got)
	}
	if got := managePerm.Can(ctx, "user4", "group5"); got != true {
		t.Fatalf("user4 group5 manage got %v want true", got)
	}
	if got := managePerm.Can(ctx, "user2", "group5"); got != false {
		t.Fatalf("user2 group5 manage got %v want false", got)
	}

	hits, err := svc.PrincipalsWithPermission(ctx, "", "group5", managePerm.ID())
	if err != nil {
		t.Fatalf("principal hits group5: %v", err)
	}
	labels := make([]string, 0, len(hits))
	for _, hit := range hits {
		labels = append(labels, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(labels)
	if len(labels) != 2 || labels[0] != "role:role.group_manager" || labels[1] != "user:user1" {
		t.Fatalf("unexpected owners for group5: %v", labels)
	}
}
