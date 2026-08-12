package inmemory

import (
	"context"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func TestIdentityProvider_GroupMembershipQueries(t *testing.T) {
	p := NewIdentityProvider()
	p.AddUserGroups("", "g-ignored")
	p.AddUserGroups("u-1")
	p.AddUserGroups("u-1", "g-1", "g-2")
	p.AddUserGroups("u-2", "g-2")

	groups, err := p.GetUserGroups(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("GetUserGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	members, err := p.GetGroupMembers(context.Background(), "g-2")
	if err != nil {
		t.Fatalf("GetGroupMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}

	inGroup, err := p.IsUserInGroup(context.Background(), "u-1", "g-1")
	if err != nil {
		t.Fatalf("IsUserInGroup: %v", err)
	}
	if !inGroup {
		t.Fatalf("expected user to be in group")
	}

	notInGroup, err := p.IsUserInGroup(context.Background(), "u-1", "missing")
	if err != nil {
		t.Fatalf("IsUserInGroup missing: %v", err)
	}
	if notInGroup {
		t.Fatalf("expected user not to be in missing group")
	}
}

func TestStore_AdditionalCoverage(t *testing.T) {
	ctx := context.Background()
	s := NewStore()

	// Cover AddGroupRoleAssignments and AssignRole validation branches.
	s.AddGroupRoleAssignments("g-1", permissions.RoleAssignment{RoleID: "r-g", BindingValues: map[string]any{"team": 1}})
	if err := s.AssignRole(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalRole, ID: "r-1"}, "r-ignored", nil); err == nil {
		t.Fatalf("expected assign role to reject role principal kind")
	}

	if err := s.AssignRole(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u-1"}, "r-u", map[string]any{"team": 42}); err != nil {
		t.Fatalf("AssignRole user: %v", err)
	}
	if err := s.UnassignRole(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u-1"}, "r-u", map[string]any{"team": 42}); err != nil {
		t.Fatalf("UnassignRole user: %v", err)
	}

	if _, err := s.GrantsForPrincipal(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u-1"}); err != nil {
		t.Fatalf("GrantsForPrincipal: %v", err)
	}

	roles, err := s.RoleDefinitions(ctx)
	if err != nil {
		t.Fatalf("RoleDefinitions: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected empty role definitions")
	}

	if _, err := s.RoleDefinition(ctx, ""); err == nil {
		t.Fatalf("expected role ID validation error")
	}
	role, err := s.RoleDefinition(ctx, "r-1")
	if err != nil {
		t.Fatalf("RoleDefinition: %v", err)
	}
	if role.ID != "r-1" {
		t.Fatalf("unexpected role ID: %s", role.ID)
	}

	if err := s.CreateRole(ctx, permissions.Role{ID: "r-1", Name: "Role 1"}); err != nil {
		t.Fatalf("CreateRole no-op failed: %v", err)
	}
	if err := s.UpdateRole(ctx, permissions.Role{ID: "r-1", Name: "Role 1"}); err != nil {
		t.Fatalf("UpdateRole no-op failed: %v", err)
	}
	if err := s.DeleteRole(ctx, "r-1"); err != nil {
		t.Fatalf("DeleteRole no-op failed: %v", err)
	}
}
