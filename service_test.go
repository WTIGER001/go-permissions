package permissions

import (
	"context"
	"fmt"
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
	lastOwners      []PrincipalRef
	rolesByID       map[string]Role
	createRoleCalls int
	grants          []Grant
	principalHits   []PrincipalHit
	writtenGrants   []Grant
	bulkWritten     []Grant
	assignedRoles   []RoleAssignment
	identityErr     error
	err             error
	disableBulk     bool
}

func (m *mockStore) GetUserGroups(_ context.Context, _ string) ([]string, error) {
	return append([]string(nil), m.groupIDs...), m.identityErr
}

func (m *mockStore) GetGroupMembers(_ context.Context, groupID string) ([]string, error) {
	if groupID == "" {
		return nil, m.identityErr
	}
	if m.userID == "" {
		return nil, m.identityErr
	}
	for _, g := range m.groupIDs {
		if g == groupID {
			return []string{m.userID}, m.identityErr
		}
	}
	return nil, m.identityErr
}

func (m *mockStore) RoleDefinitions(_ context.Context) ([]Role, error) {
	if len(m.rolesByID) == 0 {
		return []Role{}, m.err
	}
	roles := make([]Role, 0, len(m.rolesByID))
	for _, role := range m.rolesByID {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
	return roles, m.err
}

func (m *mockStore) RoleDefinition(_ context.Context, roleID string) (Role, error) {
	if role, ok := m.rolesByID[roleID]; ok {
		return role, m.err
	}
	if m.rolesByID != nil {
		return Role{}, fmt.Errorf("role not found: %s", roleID)
	}
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

func (m *mockStore) ExpandRoles(_ context.Context, roleIDs []string) ([]string, error) {
	if len(m.expandedRoleIDs) == 0 {
		return append([]string(nil), roleIDs...), m.err
	}
	return append([]string(nil), m.expandedRoleIDs...), m.err
}

func (m *mockStore) GrantsForOwners(_ context.Context, owners []PrincipalRef, _ Request) ([]Grant, error) {
	m.lastOwners = append([]PrincipalRef(nil), owners...)
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
		return false, m.identityErr
	}
	for _, g := range m.groupIDs {
		if g == groupID {
			return true, m.identityErr
		}
	}
	return false, m.identityErr
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
	m.grants = append(m.grants, grant)
	return m.err
}

func (m *mockStore) CreateGrants(_ context.Context, grants []Grant) error {
	if m.disableBulk {
		return fmt.Errorf("bulk disabled")
	}
	for _, grant := range grants {
		m.bulkWritten = append(m.bulkWritten, grant)
		m.grants = append(m.grants, grant)
	}
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

func (m *mockStore) CreateRole(_ context.Context, role Role) error {
	m.createRoleCalls++
	if m.err != nil {
		return m.err
	}
	if m.rolesByID == nil {
		m.rolesByID = map[string]Role{}
	}
	if _, exists := m.rolesByID[role.ID]; exists {
		return fmt.Errorf("role already exists: %s", role.ID)
	}
	m.rolesByID[role.ID] = role
	return nil
}
func (m *mockStore) UpdateRole(_ context.Context, _ Role) error   { return m.err }
func (m *mockStore) DeleteRole(_ context.Context, _ string) error { return m.err }
func (m *mockStore) AddRoleInheritance(_ context.Context, _, _ string) error { return m.err }

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

func TestHasPermission_EmptyUserIDSkipsIdentityLookups(t *testing.T) {
	store := &mockStore{identityErr: context.DeadlineExceeded}
	svc := NewServiceWithProviders(store, store)

	allowed, err := svc.HasPermission(context.Background(), Request{Perm: "public.read"})
	if err != nil {
		t.Fatalf("expected no error for public request, got %v", err)
	}
	if allowed {
		t.Fatalf("expected no matching grants for anonymous request")
	}
}

func TestHasFieldPermission_AllowAllWhenRestrictedFieldsEmpty(t *testing.T) {
	teamID := int64(42)
	store := &mockStore{
		grants: []Grant{{
			OwnerKind:      PrincipalUser,
			OwnerID:        "u-1",
			Effect:         EffectAllow,
			TeamScope:      "42",
			PermissionName: "billing.read",
		}},
	}

	svc := NewServiceWithProviders(store, store)
	allowed, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: &teamID, Perm: "billing.read"}, "profile.email")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Fatalf("expected field permission to be allowed")
	}
}

func TestHasFieldPermission_RestrictedAllowAndScopedDeny(t *testing.T) {
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
				OwnerKind:        PrincipalUser,
				OwnerID:          "u-1",
				Effect:           EffectDeny,
				TeamScope:        "42",
				PermissionName:   "billing.read",
				RestrictedFields: []string{"profile.secret"},
			},
		},
	}

	svc := NewServiceWithProviders(store, store)

	wholeAllowed, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", TeamID: &teamID, Perm: "billing.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !wholeAllowed {
		t.Fatalf("expected whole-object permission to remain allowed")
	}

	emailAllowed, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: &teamID, Perm: "billing.read"}, "profile.email")
	if err != nil {
		t.Fatalf("expected no error for email, got %v", err)
	}
	if !emailAllowed {
		t.Fatalf("expected profile.email to be allowed")
	}

	secretAllowed, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: &teamID, Perm: "billing.read"}, "profile.secret")
	if err != nil {
		t.Fatalf("expected no error for secret, got %v", err)
	}
	if secretAllowed {
		t.Fatalf("expected profile.secret to be denied")
	}
}

func TestHasFieldPermission_RejectsIndexedPath(t *testing.T) {
	teamID := int64(42)
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	_, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: &teamID, Perm: "billing.read"}, "items.0.name")
	if err == nil {
		t.Fatalf("expected indexed path validation error")
	}
}

func TestFilterPermittedFields_ReturnsAllowedSubset(t *testing.T) {
	teamID := int64(42)
	store := &mockStore{
		grants: []Grant{
			{
				OwnerKind:        PrincipalUser,
				OwnerID:          "u-1",
				Effect:           EffectAllow,
				TeamScope:        "42",
				PermissionName:   "billing.write",
				RestrictedFields: []string{"profile.secret", "settings.other"},
			},
			{
				OwnerKind:        PrincipalUser,
				OwnerID:          "u-1",
				Effect:           EffectDeny,
				TeamScope:        "42",
				PermissionName:   "billing.write",
				RestrictedFields: []string{"profile.email"},
			},
		},
	}

	svc := NewServiceWithProviders(store, store)
	paths, err := svc.FilterPermittedFields(context.Background(), Request{UserID: "u-1", TeamID: &teamID, Perm: "billing.write"}, []string{"profile.email", "profile.secret", "settings.theme", "settings.other"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	want := []string{"settings.theme"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("expected %v, got %v", want, paths)
	}
}

func TestHasPermission_SyntheticPublicRoleIncludedForAnonymous(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)
	svc.SetPublicRoleID(SyntheticRolePublic)

	_, err := svc.HasPermission(context.Background(), Request{Perm: "public.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !hasOwner(store.lastOwners, PrincipalRole, SyntheticRolePublic) {
		t.Fatalf("expected synthetic public role owner to be included, owners=%+v", store.lastOwners)
	}
}

func TestHasPermission_SyntheticAuthenticatedRoleIncluded(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)
	svc.SetAuthenticatedRoleID(SyntheticRoleAuthenticated)

	_, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", Perm: "any.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !hasOwner(store.lastOwners, PrincipalRole, SyntheticRoleAuthenticated) {
		t.Fatalf("expected synthetic authenticated role owner to be included, owners=%+v", store.lastOwners)
	}
}

func TestHasPermission_SyntheticAdminRoleIncludedWhenInAdminGroup(t *testing.T) {
	store := &mockStore{groupIDs: []string{"g-admin"}}
	svc := NewServiceWithProviders(store, store)
	svc.SetAdminRoleID(SyntheticRoleAdmin)
	svc.SetAdminGroupID("g-admin")

	_, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", Perm: "admin.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !hasOwner(store.lastOwners, PrincipalRole, SyntheticRoleAdmin) {
		t.Fatalf("expected synthetic admin role owner to be included, owners=%+v", store.lastOwners)
	}
}

func TestHasPermission_SyntheticAdminRoleNotIncludedWithoutAdminGroupMatch(t *testing.T) {
	store := &mockStore{groupIDs: []string{"g-users"}}
	svc := NewServiceWithProviders(store, store)
	svc.SetAdminRoleID(SyntheticRoleAdmin)
	svc.SetAdminGroupID("g-admin")

	_, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", Perm: "admin.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if hasOwner(store.lastOwners, PrincipalRole, SyntheticRoleAdmin) {
		t.Fatalf("did not expect synthetic admin role owner when user is not in admin group, owners=%+v", store.lastOwners)
	}
}

func hasOwner(owners []PrincipalRef, kind PrincipalKind, id string) bool {
	for _, owner := range owners {
		if owner.Kind == kind && owner.ID == id {
			return true
		}
	}

	return false
}

func TestEnsureSyntheticRoles_CreatesMissingRolesIdempotently(t *testing.T) {
	store := &mockStore{rolesByID: map[string]Role{}}
	svc := NewServiceWithProviders(store, store)
	svc.SetSyntheticRoleIDs(SyntheticRolePublic, SyntheticRoleAuthenticated, SyntheticRoleAdmin)

	if err := svc.EnsureSyntheticRoles(context.Background()); err != nil {
		t.Fatalf("expected no error on first ensure, got %v", err)
	}
	if err := svc.EnsureSyntheticRoles(context.Background()); err != nil {
		t.Fatalf("expected no error on second ensure, got %v", err)
	}

	if len(store.rolesByID) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(store.rolesByID))
	}
	if _, ok := store.rolesByID[SyntheticRolePublic]; !ok {
		t.Fatalf("expected %q role to exist", SyntheticRolePublic)
	}
	if _, ok := store.rolesByID[SyntheticRoleAuthenticated]; !ok {
		t.Fatalf("expected %q role to exist", SyntheticRoleAuthenticated)
	}
	if _, ok := store.rolesByID[SyntheticRoleAdmin]; !ok {
		t.Fatalf("expected %q role to exist", SyntheticRoleAdmin)
	}
}

func TestEnsureGrantForOwner_DoesNotDuplicateEquivalentGrant(t *testing.T) {
	store := &mockStore{
		grants: []Grant{{
			OwnerKind:      PrincipalRole,
			OwnerID:        SyntheticRolePublic,
			Effect:         EffectAllow,
			TeamScope:      "*",
			PermissionName: "assets.read",
		}},
	}
	svc := NewServiceWithProviders(store, store)

	err := svc.EnsureGrantForOwner(context.Background(), Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        SyntheticRolePublic,
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "assets.read",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(store.writtenGrants) != 0 {
		t.Fatalf("expected no new writes for duplicate ensure, got %d", len(store.writtenGrants))
	}
}

func TestEnsureGrantForOwner_WritesWhenMissing(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	err := svc.EnsureGrantForOwner(context.Background(), Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        SyntheticRoleAuthenticated,
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "profile.read",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(store.writtenGrants) != 1 {
		t.Fatalf("expected one grant write, got %d", len(store.writtenGrants))
	}
}

func TestSaveBuiltIns_IdempotentForConfiguredSyntheticRoles(t *testing.T) {
	store := &mockStore{rolesByID: map[string]Role{}}
	svc := NewServiceWithProviders(store, store)
	svc.SetSyntheticRoleIDs(SyntheticRolePublic, SyntheticRoleAuthenticated, SyntheticRoleAdmin)

	grants := []Grant{
		{OwnerKind: PrincipalRole, OwnerID: SyntheticRolePublic, Effect: EffectAllow, TeamScope: "*", PermissionName: "assets.read"},
		{OwnerKind: PrincipalRole, OwnerID: SyntheticRoleAuthenticated, Effect: EffectAllow, TeamScope: "*", PermissionName: "profile.read"},
		{OwnerKind: PrincipalRole, OwnerID: SyntheticRoleAdmin, Effect: EffectAllow, TeamScope: "*", PermissionName: "admin.read"},
	}

	if err := svc.SaveBuiltIns(context.Background(), grants); err != nil {
		t.Fatalf("expected no error on first save, got %v", err)
	}
	if err := svc.SaveBuiltIns(context.Background(), grants); err != nil {
		t.Fatalf("expected no error on second save, got %v", err)
	}

	if len(store.rolesByID) != 3 {
		t.Fatalf("expected 3 synthetic roles, got %d", len(store.rolesByID))
	}
	if len(store.bulkWritten) != 3 {
		t.Fatalf("expected exactly 3 grant writes after idempotent save, got %d", len(store.bulkWritten))
	}
}

func TestSaveBuiltIns_RejectsNonSyntheticOwner(t *testing.T) {
	store := &mockStore{rolesByID: map[string]Role{}}
	svc := NewServiceWithProviders(store, store)
	svc.SetSyntheticRoleIDs(SyntheticRolePublic, SyntheticRoleAuthenticated, SyntheticRoleAdmin)

	err := svc.SaveBuiltIns(context.Background(), []Grant{{
		OwnerKind:      PrincipalRole,
		OwnerID:        "role.custom",
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "custom.read",
	}})
	if err == nil {
		t.Fatalf("expected validation error for non-synthetic owner")
	}
}

func TestNew_UsesDefaultStoreAndNilIdentity(t *testing.T) {
	svc := New()
	if svc == nil {
		t.Fatalf("expected service instance")
	}

	allowed, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", Perm: "any.read"})
	if err != nil {
		t.Fatalf("expected nil-identity fallback without error, got %v", err)
	}
	if allowed {
		t.Fatalf("expected no permissions by default")
	}
}

func TestSetStore_TriggersSaveBuiltIns(t *testing.T) {
	targetStore := &mockStore{rolesByID: map[string]Role{}}
	svc := New()
	svc.SetSyntheticRoleIDs(SyntheticRolePublic, SyntheticRoleAuthenticated, SyntheticRoleAdmin)
	svc.SetBuiltInGrants([]Grant{{
		OwnerKind:      PrincipalRole,
		OwnerID:        SyntheticRolePublic,
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "assets.read",
	}})

	if err := svc.SetStore(targetStore); err != nil {
		t.Fatalf("expected SetStore to save built-ins, got %v", err)
	}

	if _, ok := targetStore.rolesByID[SyntheticRolePublic]; !ok {
		t.Fatalf("expected synthetic public role to be created in new store")
	}
	if len(targetStore.bulkWritten) != 1 {
		t.Fatalf("expected 1 built-in grant write, got %d", len(targetStore.bulkWritten))
	}
}

func TestNew_DefaultsSyntheticRoleIDs(t *testing.T) {
	svc := New()
	if svc.publicRoleID != SyntheticRolePublic {
		t.Fatalf("expected default public role ID %q, got %q", SyntheticRolePublic, svc.publicRoleID)
	}
	if svc.authenticatedRoleID != SyntheticRoleAuthenticated {
		t.Fatalf("expected default authenticated role ID %q, got %q", SyntheticRoleAuthenticated, svc.authenticatedRoleID)
	}
	if svc.adminRoleID != SyntheticRoleAdmin {
		t.Fatalf("expected default admin role ID %q, got %q", SyntheticRoleAdmin, svc.adminRoleID)
	}
}

func TestAddDefaultGrant_AppendsAndDeduplicates(t *testing.T) {
	svc := New()

	svc.AddDefaultGrant(SyntheticRolePublic, "assets.read", "")
	svc.AddDefaultGrant(SyntheticRolePublic, "assets.read", "*")

	if len(svc.builtInGrants) != 1 {
		t.Fatalf("expected a single deduplicated built-in grant, got %d", len(svc.builtInGrants))
	}
	grant := svc.builtInGrants[0]
	if grant.OwnerKind != PrincipalRole || grant.OwnerID != SyntheticRolePublic {
		t.Fatalf("unexpected grant owner %+v", grant)
	}
	if grant.Effect != EffectAllow || grant.TeamScope != "*" || grant.PermissionName != "assets.read" {
		t.Fatalf("unexpected grant payload %+v", grant)
	}
}

func TestAddDefaultGrant_ValidatesInputs(t *testing.T) {
	t.Run("missing role id panics", func(t *testing.T) {
		svc := New()
		defer func() {
			if recover() == nil {
				t.Fatalf("expected panic for missing role ID")
			}
		}()
		svc.AddDefaultGrant("", "assets.read", "*")
	})

	t.Run("missing permission panics", func(t *testing.T) {
		svc := New()
		defer func() {
			if recover() == nil {
				t.Fatalf("expected panic for missing permission")
			}
		}()
		svc.AddDefaultGrant(SyntheticRolePublic, "", "*")
	})
}

func TestAddDefaultSystemCRUDGrants_AppendsAllPermissions(t *testing.T) {
	svc := New()
	crud := NewSystemCRUDPermissions("announcements.announcement")

	svc.AddDefaultSystemCRUDGrants(SyntheticRoleAdmin, "*", crud)

	if len(svc.builtInGrants) != 5 {
		t.Fatalf("expected 5 built-in grants, got %d", len(svc.builtInGrants))
	}
}

func TestAddDefaultTeamCRUDGrants_AppendsAllPermissions(t *testing.T) {
	svc := New()
	crud := NewTeamCRUDPermissions("announcements.teamannouncement")

	svc.AddDefaultTeamCRUDGrants(SyntheticRoleAdmin, "*", crud)

	if len(svc.builtInGrants) != 5 {
		t.Fatalf("expected 5 built-in grants, got %d", len(svc.builtInGrants))
	}
}

func TestAddDefaultCRUDGrant_ValidatesAction(t *testing.T) {
	svc := New()

	svc.AddDefaultCRUDGrant(SyntheticRoleAdmin, "*", CRUDRead, "announcements.read")
	if len(svc.builtInGrants) != 1 {
		t.Fatalf("expected 1 built-in grant, got %d", len(svc.builtInGrants))
	}

	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for invalid CRUD action")
		}
	}()

	svc.AddDefaultCRUDGrant(SyntheticRoleAdmin, "*", CRUDAction("invalid"), "announcements.invalid")
}

func TestCreateGrants_UsesBulkStoreWhenAvailable(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	err := svc.CreateGrants(context.Background(), []Grant{{
		OwnerKind:      PrincipalRole,
		OwnerID:        SyntheticRoleAdmin,
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "announcements.read",
	}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(store.bulkWritten) != 1 {
		t.Fatalf("expected 1 bulk grant write, got %d", len(store.bulkWritten))
	}
	if len(store.writtenGrants) != 0 {
		t.Fatalf("expected no single grant writes when bulk path is used")
	}
}

func TestEnsureGrantsForOwners_WritesOnlyMissing(t *testing.T) {
	existing := Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        SyntheticRoleAdmin,
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "announcements.read",
	}
	missing := Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        SyntheticRoleAdmin,
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "announcements.update",
	}

	store := &mockStore{grants: []Grant{existing}}
	svc := NewServiceWithProviders(store, store)

	err := svc.EnsureGrantsForOwners(context.Background(), []Grant{existing, missing})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(store.bulkWritten) != 1 {
		t.Fatalf("expected 1 missing grant write, got %d", len(store.bulkWritten))
	}
	if store.bulkWritten[0].PermissionName != "announcements.update" {
		t.Fatalf("expected update permission to be written, got %q", store.bulkWritten[0].PermissionName)
	}
}

func TestSaveBuiltIns_UsesBulkEnsurePath(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	err := svc.SaveBuiltIns(context.Background(), []Grant{{
		OwnerKind:      PrincipalRole,
		OwnerID:        SyntheticRolePublic,
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "assets.read",
	}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(store.bulkWritten) != 1 {
		t.Fatalf("expected built-ins to be written through bulk path")
	}
}

func TestHasPermission_MultiTenantRole_BothTeamsAllowed(t *testing.T) {
	team42 := int64(42)
	team99 := int64(99)

	store := &mockStore{
		roleAssignments: []RoleAssignment{
			{RoleID: "r-viewer", BindingValues: map[string]any{"team": 42}},
			{RoleID: "r-viewer", BindingValues: map[string]any{"team": 99}},
		},
		grants: []Grant{
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-viewer",
				Effect:         EffectAllow,
				TeamScope:      "?team",
				PermissionName: "billing.read",
				VariableSpec:   map[string]any{"team": "required"},
			},
		},
	}

	svc := NewServiceWithProviders(store, store)

	allowed, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		TeamID: &team42,
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Fatalf("expected team 42 to be allowed")
	}

	allowed, err = svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		TeamID: &team99,
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Fatalf("expected team 99 to be allowed")
	}
}

func TestHasPermission_MultiTenantRole_DenyInOneTeam(t *testing.T) {
	team42 := int64(42)
	team99 := int64(99)

	store := &mockStore{
		roleAssignments: []RoleAssignment{
			{RoleID: "r-viewer", BindingValues: map[string]any{"team": 42}},
			{RoleID: "r-viewer", BindingValues: map[string]any{"team": 99}},
		},
		grants: []Grant{
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-viewer",
				Effect:         EffectAllow,
				TeamScope:      "?team",
				PermissionName: "billing.read",
				VariableSpec:   map[string]any{"team": "required"},
			},
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-viewer",
				Effect:         EffectDeny,
				TeamScope:      "99",
				PermissionName: "billing.read",
			},
		},
	}

	svc := NewServiceWithProviders(store, store)

	allowed, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		TeamID: &team42,
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Fatalf("expected team 42 to be allowed")
	}

	allowed, err = svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		TeamID: &team99,
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Fatalf("expected team 99 to be denied due to explicit deny grant")
	}
}

func TestEffectivePermissions_MultiTenantRole(t *testing.T) {
	team42 := int64(42)

	store := &mockStore{
		roleAssignments: []RoleAssignment{
			{RoleID: "r-viewer", BindingValues: map[string]any{"team": 42}},
			{RoleID: "r-viewer", BindingValues: map[string]any{"team": 99}},
		},
		grants: []Grant{
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-viewer",
				Effect:         EffectAllow,
				TeamScope:      "?team",
				PermissionName: "billing.read",
				VariableSpec:   map[string]any{"team": "required"},
			},
		},
	}

	svc := NewServiceWithProviders(store, store)

	eff, err := svc.EffectivePermissions(context.Background(), "u-1", &team42)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// For teamID = 42, we expect only the grant resolved for team 42 to be present.
	// The grant resolved for team 99 does not match teamID = 42 scope.
	if len(eff) != 1 {
		t.Fatalf("expected exactly 1 effective permission, got %d", len(eff))
	}
	if eff[0].TeamScope != "42" {
		t.Fatalf("expected team scope 42, got %q", eff[0].TeamScope)
	}
}
