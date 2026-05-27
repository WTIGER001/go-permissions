package permissions

import (
	"context"
	"reflect"
	"testing"
)

type mockStore struct {
	groupIDs        []string
	userID          string
	roleAssignments []RoleAssignment
	expandedRoleIDs []string
	grants          []Grant
	err             error
}

func (m *mockStore) ListKnownGroupIDs(_ context.Context) ([]string, error) {
	return append([]string(nil), m.groupIDs...), m.err
}

func (m *mockStore) IsUserInGroup(_ context.Context, userID, groupID string) (bool, error) {
	if m.userID != "" && userID != m.userID {
		return false, m.err
	}
	for _, g := range m.groupIDs {
		if g == groupID {
			return true, m.err
		}
	}
	return false, m.err
}

func (m *mockStore) ListUserGroupIDs(_ context.Context, _ string) ([]string, error) {
	return append([]string(nil), m.groupIDs...), m.err
}

func (m *mockStore) ListRoleAssignmentsForUserAndGroups(_ context.Context, _ string, _ []string) ([]RoleAssignment, error) {
	return append([]RoleAssignment(nil), m.roleAssignments...), m.err
}

func (m *mockStore) ListExpandedRoleIDs(_ context.Context, _ []string) ([]string, error) {
	return append([]string(nil), m.expandedRoleIDs...), m.err
}

func (m *mockStore) ListGrantsForOwners(_ context.Context, _ []PrincipalRef, _ Request) ([]Grant, error) {
	return append([]Grant(nil), m.grants...), m.err
}

func TestHasPermission_DenyOverridesAllow(t *testing.T) {
	teamID := int64(42)
	store := &mockStore{
		grants: []Grant{
			{
				OwnerKind:      PrincipalUser,
				OwnerID:        "u-1",
				Effect:         EffectAllow,
				TeamScope:      "42",
				PermissionName: "billing.read",
			},
			{
				OwnerKind:      PrincipalGroup,
				OwnerID:        "g-1",
				Effect:         EffectDeny,
				TeamScope:      "42",
				PermissionName: "billing.read",
			},
		},
	}

	svc := NewService(store)
	allowed, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		TeamID: &teamID,
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Fatalf("expected permission denied due to matching deny grant")
	}
}

func TestHasPermission_StrictMissingBindingReturnsError(t *testing.T) {
	teamID := int64(42)
	store := &mockStore{
		expandedRoleIDs: []string{"r-1"},
		grants: []Grant{
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-1",
				Effect:         EffectAllow,
				TeamScope:      "?team",
				PermissionName: "billing.read",
				VariableSpec: map[string]any{
					"team": "required",
				},
			},
		},
	}

	svc := NewService(store)
	_, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		TeamID: &teamID,
		Perm:   "billing.read",
	})
	if err == nil {
		t.Fatalf("expected strict binding error, got nil")
	}
}

func TestEffectivePermissions_DenyRemovesAllow(t *testing.T) {
	teamID := int64(7)
	store := &mockStore{
		grants: []Grant{
			{
				OwnerKind:      PrincipalUser,
				OwnerID:        "u-1",
				Effect:         EffectAllow,
				TeamScope:      "7",
				PermissionName: "report.read",
			},
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-9",
				Effect:         EffectDeny,
				TeamScope:      "7",
				PermissionName: "report.read",
			},
			{
				OwnerKind:      PrincipalUser,
				OwnerID:        "u-1",
				Effect:         EffectAllow,
				TeamScope:      "7",
				PermissionName: "report.write",
			},
		},
	}

	svc := NewService(store)
	effective, err := svc.EffectivePermissions(context.Background(), "u-1", &teamID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(effective) != 1 {
		t.Fatalf("expected one effective permission, got %d", len(effective))
	}

	got := effective[0]
	if got.PermissionName != "report.write" {
		t.Fatalf("expected report.write, got %q", got.PermissionName)
	}

	if !reflect.DeepEqual(got.Source, PrincipalRef{Kind: PrincipalUser, ID: "u-1"}) {
		t.Fatalf("unexpected source %+v", got.Source)
	}
}
