package permissions

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"
)

type mockStore struct {
	groupIDs        []string
	userID          string
	roleAssignments []RoleAssignment
	expandedRoleIDs []string
	grants          []Grant
	principalHits   []PrincipalHit
	writtenGrants   []Grant
	assignedRoles   []RoleAssignment
	err             error
}

func (m *mockStore) GetUserGroups(_ context.Context, _ string) ([]string, error) {
	return append([]string(nil), m.groupIDs...), m.err
}

func (m *mockStore) GetGroupMembers(_ context.Context, groupID string) ([]string, error) {
	if groupID == "" {
		return nil, m.err
	}
	if m.userID == "" {
		return nil, m.err
	}
	for _, g := range m.groupIDs {
		if g == groupID {
			return []string{m.userID}, m.err
		}
	}
	return nil, m.err
}

func (m *mockStore) RoleDefinitions(_ context.Context) ([]Role, error) {
	return []Role{}, m.err
}

func (m *mockStore) RoleDefinition(_ context.Context, roleID string) (Role, error) {
	return Role{ID: roleID, Name: roleID}, m.err
}

func (m *mockStore) RoleAssignmentsForPrincipal(_ context.Context, principal PrincipalRef) ([]RoleAssignment, error) {
	if principal.Kind == PrincipalUser || principal.Kind == PrincipalGroup {
		return append([]RoleAssignment(nil), m.roleAssignments...), m.err
	}
	return nil, m.err
}

func (m *mockStore) GrantsForPrincipal(_ context.Context, _ PrincipalRef) ([]Grant, error) {
	return append([]Grant(nil), m.grants...), m.err
}

func (m *mockStore) ExpandRoles(_ context.Context, _ []string) ([]string, error) {
	return append([]string(nil), m.expandedRoleIDs...), m.err
}

func (m *mockStore) GrantsForOwners(_ context.Context, _ []PrincipalRef, _ Request) ([]Grant, error) {
	return append([]Grant(nil), m.grants...), m.err
}

func (m *mockStore) PrincipalsWithGrant(_ context.Context, _ Request) ([]PrincipalHit, error) {
	return append([]PrincipalHit(nil), m.principalHits...), m.err
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

func (m *mockStore) ListPrincipalsWithGrant(_ context.Context, _ Request) ([]PrincipalHit, error) {
	return append([]PrincipalHit(nil), m.principalHits...), m.err
}

func (m *mockStore) CreateGrant(_ context.Context, grant Grant) error {
	m.writtenGrants = append(m.writtenGrants, grant)
	return m.err
}

func (m *mockStore) AssignRole(_ context.Context, principal PrincipalRef, roleID string, bindingValues map[string]any) error {
	assignment := RoleAssignment{RoleID: roleID, BindingValues: map[string]any{}}
	for k, v := range bindingValues {
		assignment.BindingValues[k] = v
	}
	assignment.BindingValues["principal_kind"] = string(principal.Kind)
	assignment.BindingValues["principal_id"] = principal.ID
	m.assignedRoles = append(m.assignedRoles, assignment)
	return m.err
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

	svc := NewServiceWithProviders(store, store)
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

	svc := NewServiceWithProviders(store, store)
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

	svc := NewServiceWithProviders(store, store)
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

func TestPrincipalsWithPermission_DenyOverridesAllow(t *testing.T) {
	teamID := int64(42)
	store := &mockStore{
		principalHits: []PrincipalHit{
			{Kind: PrincipalRole, ID: "r-2", TeamScope: "*", PermissionName: "billing.read"},
			{Kind: PrincipalGroup, ID: "g-2", TeamScope: "42", PermissionName: "billing.read"},
			{Kind: PrincipalUser, ID: "u-1", TeamScope: "42", PermissionName: "billing.read"},
		},
	}

	svc := NewServiceWithProviders(store, store)
	hits, err := svc.PrincipalsWithPermission(context.Background(), &teamID, "billing", "billing.read")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(hits) != 3 {
		t.Fatalf("expected 3 hits, got %d", len(hits))
	}

	got := make([]string, 0, len(hits))
	for _, hit := range hits {
		got = append(got, string(hit.Kind)+":"+hit.ID)
	}

	sort.Strings(got)
	expected := []string{"group:g-2", "role:r-2", "user:u-1"}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

func TestPrincipalsWithPermission_Validation(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	teamID := int64(0)
	if _, err := svc.PrincipalsWithPermission(context.Background(), &teamID, "", "billing.read"); err == nil {
		t.Fatalf("expected invalid team ID error")
	}

	if _, err := svc.PrincipalsWithPermission(context.Background(), nil, "", ""); err == nil {
		t.Fatalf("expected empty permission error")
	}
}

func TestAllowUser_WritesGrant(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	objectID := "group-1"
	if err := svc.AllowUser(context.Background(), "u-1", "groups.members.manage", &objectID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(store.writtenGrants) != 1 {
		t.Fatalf("expected one written grant, got %d", len(store.writtenGrants))
	}

	got := store.writtenGrants[0]
	if got.OwnerKind != PrincipalUser || got.OwnerID != "u-1" {
		t.Fatalf("unexpected owner %+v", got)
	}
	if got.Effect != EffectAllow || got.PermissionName != "groups.members.manage" || got.TeamScope != "*" {
		t.Fatalf("unexpected grant values %+v", got)
	}
	if got.ObjectScope == nil || *got.ObjectScope != objectID {
		t.Fatalf("unexpected object scope %+v", got.ObjectScope)
	}
}

func TestAssignRoleToUser_WritesAssignment(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	if err := svc.AssignRoleToUser(context.Background(), "u-7", "role.group_manager", map[string]any{"team": 42}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(store.assignedRoles) != 1 {
		t.Fatalf("expected one role assignment write, got %d", len(store.assignedRoles))
	}

	got := store.assignedRoles[0]
	if got.RoleID != "role.group_manager" {
		t.Fatalf("unexpected role ID %q", got.RoleID)
	}
	if got.BindingValues["principal_kind"] != "user" || got.BindingValues["principal_id"] != "u-7" {
		t.Fatalf("unexpected principal binding %+v", got.BindingValues)
	}
}

func TestAllowUserFor_WritesExpiringGrant(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	if err := svc.AllowUserFor(context.Background(), "u-1", "groups.members.manage", nil, 5*time.Minute); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(store.writtenGrants) != 1 {
		t.Fatalf("expected one written grant, got %d", len(store.writtenGrants))
	}

	got := store.writtenGrants[0]
	if got.ExpiresAt == nil {
		t.Fatalf("expected expires_at to be set")
	}
	if !got.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("expected expires_at in the future, got %v", got.ExpiresAt)
	}
}

func TestAllowUserFor_RejectsNonPositiveTTL(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	if err := svc.AllowUserFor(context.Background(), "u-1", "groups.members.manage", nil, 0); err == nil {
		t.Fatalf("expected ttl validation error")
	}
}

func TestHasPermission_IgnoresExpiredGrant(t *testing.T) {
	teamID := int64(42)
	expiredAt := time.Now().UTC().Add(-1 * time.Minute)
	store := &mockStore{
		grants: []Grant{
			{
				OwnerKind:      PrincipalUser,
				OwnerID:        "u-1",
				Effect:         EffectAllow,
				TeamScope:      "42",
				PermissionName: "billing.read",
				ExpiresAt:      &expiredAt,
			},
		},
	}

	svc := NewServiceWithProviders(store, store)
	allowed, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", TeamID: &teamID, Perm: "billing.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Fatalf("expected expired grant to be ignored")
	}
}
