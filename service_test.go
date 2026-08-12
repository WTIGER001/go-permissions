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
	if len(owners) == 0 {
		return nil, m.err
	}
	ownerMap := make(map[string]bool)
	for _, o := range owners {
		ownerMap[string(o.Kind)+":"+o.ID] = true
	}
	var filtered []Grant
	for _, g := range m.grants {
		if ownerMap[string(g.OwnerKind)+":"+g.OwnerID] {
			filtered = append(filtered, g)
		}
	}
	return filtered, m.err
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

func (m *mockStore) ListGrantsForOwners(_ context.Context, owners []PrincipalRef, _ Request) ([]Grant, error) {
	if len(owners) == 0 {
		return nil, m.err
	}
	ownerMap := make(map[string]bool)
	for _, o := range owners {
		ownerMap[string(o.Kind)+":"+o.ID] = true
	}
	var filtered []Grant
	for _, g := range m.grants {
		if ownerMap[string(g.OwnerKind)+":"+g.OwnerID] {
			filtered = append(filtered, g)
		}
	}
	return filtered, m.err
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


func (m *mockStore) UnassignRole(
    _ context.Context,
    principal PrincipalRef,
    roleID string,
    bindingValues map[string]any,
) error {
    assignments := m.assignedRoles
    found := false
    filtered := assignments[:0]

    for _, a := range assignments {
        // Must match the roleID
        if a.RoleID != roleID {
            filtered = append(filtered, a)
            continue
        }

        // Must match binding values exactly
        if !BindingValuesEqual(a.BindingValues, bindingValues) {
            filtered = append(filtered, a)
            continue
        }

        // Must match principal identity
        if a.BindingValues["principal_kind"] != string(principal.Kind) ||
           a.BindingValues["principal_id"] != principal.ID {
            filtered = append(filtered, a)
            continue
        }

        // If we got here, we found the exact assignment; skip it (remove)
        found = true
    }

    if !found {
        return fmt.Errorf("role %q was not assigned to principal %s", roleID, principal.ID)
    }

    m.assignedRoles = filtered
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
func (m *mockStore) UpdateRole(_ context.Context, _ Role) error              { return m.err }
func (m *mockStore) DeleteRole(_ context.Context, _ string) error            { return m.err }
func (m *mockStore) AddRoleInheritance(_ context.Context, _, _ string) error { return m.err }
func (m *mockStore) DeleteGrantsForOwner(_ context.Context, _ PrincipalKind, _ string) error {
	return m.err
}
func (m *mockStore) DisableBuiltInRole(_ context.Context, _ string) error     { return m.err }
func (m *mockStore) EnableBuiltInRole(_ context.Context, _ string) error      { return m.err }
func (m *mockStore) DisabledBuiltInRoles(_ context.Context) ([]string, error) { return nil, m.err }
func (m *mockStore) ListGrants(_ context.Context, _ GrantQuery) (GrantQueryResult, error) {
	return GrantQueryResult{}, m.err
}

func TestHasPermission_DenyOverridesAllow(t *testing.T) {
	teamID := "42"
	store := &mockStore{
		groupIDs: []string{"g-1"},
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
		TeamID: teamID,
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
	teamID := "42"
	store := &mockStore{
		roleAssignments: []RoleAssignment{{RoleID: "r-1"}},
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
		TeamID: teamID,
		Perm:   "billing.read",
	})
	if err == nil {
		t.Fatalf("expected strict binding error, got nil")
	}
}

func TestEffectivePermissions_DenyRemovesAllow(t *testing.T) {
	teamID := "7"
	store := &mockStore{
		roleAssignments: []RoleAssignment{
			{RoleID: "r-9"},
		},
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
	effective, err := svc.EffectivePermissions(context.Background(), "u-1", teamID)
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
	teamID := "42"
	store := &mockStore{
		principalHits: []PrincipalHit{
			{Kind: PrincipalRole, ID: "r-2", TeamScope: "*", PermissionName: "billing.read"},
			{Kind: PrincipalGroup, ID: "g-2", TeamScope: "42", PermissionName: "billing.read"},
			{Kind: PrincipalUser, ID: "u-1", TeamScope: "42", PermissionName: "billing.read"},
		},
	}

	svc := NewServiceWithProviders(store, store)
	hits, err := svc.PrincipalsWithPermission(context.Background(), teamID, "billing", "billing.read")
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

	if _, err := svc.PrincipalsWithPermission(context.Background(), "", "", ""); err == nil {
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
	teamID := "42"
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
	allowed, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", TeamID: teamID, Perm: "billing.read"})
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
	teamID := "42"
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
	allowed, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: teamID, Perm: "billing.read"}, "profile.email")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !allowed {
		t.Fatalf("expected field permission to be allowed")
	}
}

func TestHasFieldPermission_RestrictedAllowAndScopedDeny(t *testing.T) {
	teamID := "42"
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

	wholeAllowed, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", TeamID: teamID, Perm: "billing.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !wholeAllowed {
		t.Fatalf("expected whole-object permission to remain allowed")
	}

	emailAllowed, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: teamID, Perm: "billing.read"}, "profile.email")
	if err != nil {
		t.Fatalf("expected no error for email, got %v", err)
	}
	if !emailAllowed {
		t.Fatalf("expected profile.email to be allowed")
	}

	secretAllowed, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: teamID, Perm: "billing.read"}, "profile.secret")
	if err != nil {
		t.Fatalf("expected no error for secret, got %v", err)
	}
	if secretAllowed {
		t.Fatalf("expected profile.secret to be denied")
	}
}

func TestHasFieldPermission_RejectsIndexedPath(t *testing.T) {
	teamID := "42"
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)

	_, err := svc.HasFieldPermission(context.Background(), Request{UserID: "u-1", TeamID: teamID, Perm: "billing.read"}, "items.0.name")
	if err == nil {
		t.Fatalf("expected indexed path validation error")
	}
}

func TestFilterPermittedFields_ReturnsAllowedSubset(t *testing.T) {
	teamID := "42"
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
	paths, err := svc.FilterPermittedFields(context.Background(), Request{UserID: "u-1", TeamID: teamID, Perm: "billing.write"}, []string{"profile.email", "profile.secret", "settings.theme", "settings.other"})
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
	svc.AddDefaultGrant(SyntheticRolePublic, "public.read", "*")

	ok, err := svc.HasPermission(context.Background(), Request{Perm: "public.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected permission allowed via synthetic public role")
	}
}

func TestHasPermission_SyntheticAuthenticatedRoleIncluded(t *testing.T) {
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)
	svc.SetAuthenticatedRoleID(SyntheticRoleAuthenticated)
	svc.AddDefaultGrant(SyntheticRoleAuthenticated, "any.read", "*")

	ok, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", Perm: "any.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected permission allowed via synthetic authenticated role")
	}
}

func TestHasPermission_SyntheticAdminRoleIncludedWhenInAdminGroup(t *testing.T) {
	store := &mockStore{groupIDs: []string{"g-admin"}}
	svc := NewServiceWithProviders(store, store)
	svc.SetAdminRoleID(SyntheticRoleAdmin)
	svc.SetAdminGroupID("g-admin")
	svc.AddDefaultGrant(SyntheticRoleAdmin, "admin.read", "*")

	ok, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", Perm: "admin.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !ok {
		t.Fatalf("expected permission allowed via synthetic admin role")
	}
}

func TestHasPermission_SyntheticAdminRoleNotIncludedWithoutAdminGroupMatch(t *testing.T) {
	store := &mockStore{groupIDs: []string{"g-users"}}
	svc := NewServiceWithProviders(store, store)
	svc.SetAdminRoleID(SyntheticRoleAdmin)
	svc.SetAdminGroupID("g-admin")
	svc.AddDefaultGrant(SyntheticRoleAdmin, "admin.read", "*")

	ok, err := svc.HasPermission(context.Background(), Request{UserID: "u-1", Perm: "admin.read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ok {
		t.Fatalf("did not expect synthetic admin role permission when user is not in admin group")
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
	store := &mockStore{}
	svc := NewServiceWithProviders(store, store)
	svc.SetSyntheticRoleIDs(SyntheticRolePublic, SyntheticRoleAuthenticated, SyntheticRoleAdmin)

	if err := svc.EnsureSyntheticRoles(context.Background()); err != nil {
		t.Fatalf("expected no error on first ensure, got %v", err)
	}
	if err := svc.EnsureSyntheticRoles(context.Background()); err != nil {
		t.Fatalf("expected no error on second ensure, got %v", err)
	}

	roles, err := svc.RoleDefinitions(context.Background())
	if err != nil {
		t.Fatalf("expected role definitions to succeed, got %v", err)
	}
	if len(roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(roles))
	}
	if _, err := svc.RoleDefinition(context.Background(), SyntheticRolePublic); err != nil {
		t.Fatalf("expected %q role to exist", SyntheticRolePublic)
	}
	if _, err := svc.RoleDefinition(context.Background(), SyntheticRoleAuthenticated); err != nil {
		t.Fatalf("expected %q role to exist", SyntheticRoleAuthenticated)
	}
	if _, err := svc.RoleDefinition(context.Background(), SyntheticRoleAdmin); err != nil {
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
	store := &mockStore{}
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

	roles, err := svc.RoleDefinitions(context.Background())
	if err != nil {
		t.Fatalf("expected role definitions to succeed, got %v", err)
	}
	if len(roles) != 3 {
		t.Fatalf("expected 3 synthetic roles in memory, got %d", len(roles))
	}
	if len(svc.builtIns.grants) != 3 {
		t.Fatalf("expected exactly 3 grants in memory after idempotent save, got %d", len(svc.builtIns.grants))
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
	targetStore := &mockStore{}
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
		t.Fatalf("expected SetStore to succeed, got %v", err)
	}

	if _, err := svc.RoleDefinition(context.Background(), SyntheticRolePublic); err != nil {
		t.Fatalf("expected synthetic public role to be accessible in memory")
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

	if len(svc.builtIns.grants) != 1 {
		t.Fatalf("expected a single deduplicated built-in grant, got %d", len(svc.builtIns.grants))
	}
	grant := svc.builtIns.grants[0]
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

	if len(svc.builtIns.grants) != 5 {
		t.Fatalf("expected 5 built-in grants, got %d", len(svc.builtIns.grants))
	}
}

func TestAddDefaultTeamCRUDGrants_AppendsAllPermissions(t *testing.T) {
	svc := New()
	crud := NewTeamCRUDPermissions("announcements.teamannouncement")

	svc.AddDefaultTeamCRUDGrants(SyntheticRoleAdmin, "*", crud)

	if len(svc.builtIns.grants) != 5 {
		t.Fatalf("expected 5 built-in grants, got %d", len(svc.builtIns.grants))
	}
}

func TestAddDefaultCRUDGrant_ValidatesAction(t *testing.T) {
	svc := New()

	svc.AddDefaultCRUDGrant(SyntheticRoleAdmin, "*", CRUDRead, "announcements.read")
	if len(svc.builtIns.grants) != 1 {
		t.Fatalf("expected 1 built-in grant, got %d", len(svc.builtIns.grants))
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
	if len(svc.builtIns.grants) != 1 {
		t.Fatalf("expected built-ins to be stored in memory")
	}
}

func TestHasPermission_MultiTenantRole_BothTeamsAllowed(t *testing.T) {
	team42 := "42"
	team99 := "99"

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
		TeamID: team42,
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
		TeamID: team99,
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
	team42 := "42"
	team99 := "99"

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
		TeamID: team42,
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
		TeamID: team99,
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
	team42 := "42"

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

	eff, err := svc.EffectivePermissions(context.Background(), "u-1", team42)
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

func TestHasPermission_DisabledRole(t *testing.T) {
	store := &mockStore{
		roleAssignments: []RoleAssignment{
			{RoleID: "r-operator"},
		},
		rolesByID: map[string]Role{
			"r-operator": {
				ID:         "r-operator",
				Name:       "Operator",
				IsDisabled: true, // Disabled directly!
			},
		},
		grants: []Grant{
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-operator",
				Effect:         EffectAllow,
				TeamScope:      "*",
				PermissionName: "backup.run",
			},
		},
	}

	svc := NewServiceWithProviders(store, store)

	allowed, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		Perm:   "backup.run",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Fatalf("expected permission to be denied because the role is disabled")
	}
}

func TestHasPermission_DisabledRoleInherited(t *testing.T) {
	store := &mockStore{
		roleAssignments: []RoleAssignment{
			{RoleID: "r-custom-operator"},
		},
		rolesByID: map[string]Role{
			"r-custom-operator": {
				ID:   "r-custom-operator",
				Name: "Custom Operator",
			},
			"r-operator": {
				ID:         "r-operator",
				Name:       "Operator",
				IsDisabled: true, // Inherited role is disabled!
			},
		},
		expandedRoleIDs: []string{"r-custom-operator", "r-operator"},
		grants: []Grant{
			{
				OwnerKind:      PrincipalRole,
				OwnerID:        "r-operator",
				Effect:         EffectAllow,
				TeamScope:      "*",
				PermissionName: "backup.run",
			},
		},
	}

	svc := NewServiceWithProviders(store, store)

	allowed, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-1",
		Perm:   "backup.run",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if allowed {
		t.Fatalf("expected permission to be denied because the inherited role is disabled")
	}
}

func TestService_AddBuiltInRole(t *testing.T) {
	store := newBootstrapStore()
	svc := NewServiceWithProviders(store, nil)

	role := Role{
		ID:          "builtin.operator",
		Name:        "Operator",
		Description: "Backup operator description",
		Permissions: []string{"backup.run", "backup.list"},
	}

	// 1. First Boot: Should create the role with BuiltIn = true and register grants
	err := svc.AddBuiltInRole(context.Background(), role)
	if err != nil {
		t.Fatalf("expected no error during first bootstrap, got %v", err)
	}

	dbRole, err := svc.RoleDefinition(context.Background(), "builtin.operator")
	if err != nil {
		t.Fatalf("expected role definition to exist, got %v", err)
	}
	if !dbRole.BuiltIn {
		t.Fatalf("expected role to be marked as BuiltIn")
	}
	if dbRole.Name != "Operator" {
		t.Fatalf("expected role name to be Operator, got %q", dbRole.Name)
	}

	grants := svc.builtIns.GrantsForOwners([]PrincipalRef{{Kind: PrincipalRole, ID: "builtin.operator"}}, Request{})
	if len(grants) != 2 {
		t.Fatalf("expected exactly 2 grants, got %d", len(grants))
	}

	// 2. Second Boot (Upgrade): Should update description and idempotently preserve grants
	role.Description = "Updated description"
	role.Permissions = append(role.Permissions, "backup.download")

	err = svc.AddBuiltInRole(context.Background(), role)
	if err != nil {
		t.Fatalf("expected no error during second bootstrap, got %v", err)
	}

	dbRole2, err := svc.RoleDefinition(context.Background(), "builtin.operator")
	if err != nil {
		t.Fatalf("expected role definition to exist, got %v", err)
	}
	if dbRole2.Description != "Updated description" {
		t.Fatalf("expected role description to be updated, got %q", dbRole2.Description)
	}

	grants2 := svc.builtIns.GrantsForOwners([]PrincipalRef{{Kind: PrincipalRole, ID: "builtin.operator"}}, Request{})
	if len(grants2) != 3 {
		t.Fatalf("expected exactly 3 grants after upgrade, got %d", len(grants2))
	}
}

func TestService_ProxyMethods(t *testing.T) {
	store := newBootstrapStore()
	svc := NewServiceWithProviders(store, nil)

	ctx := context.Background()

	// Test GetStore
	if svc.GetStore() != store {
		t.Errorf("expected GetStore to return the underlying store")
	}

	// Test AddBuiltInRole
	builtInRole := Role{
		ID:          "builtin.editor",
		Name:        "Editor",
		Permissions: []string{"write", "read"},
	}
	if err := svc.AddBuiltInRole(ctx, builtInRole); err != nil {
		t.Fatalf("AddBuiltInRole failed: %v", err)
	}

	// Test CreateRole & UpdateRole & DeleteRole for custom role
	customRole := Role{
		ID:   "role.custom",
		Name: "Custom Role",
	}
	if err := svc.CreateRole(ctx, customRole); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	customRole.Name = "Updated Custom Role"
	if err := svc.UpdateRole(ctx, customRole); err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}

	// Built-in role updates/deletions should fail
	if err := svc.UpdateRole(ctx, builtInRole); err == nil {
		t.Error("expected error updating built-in role")
	}
	if err := svc.DeleteRole(ctx, builtInRole.ID); err == nil {
		t.Error("expected error deleting built-in role")
	}

	// Test AssignRole and RoleAssignmentsForPrincipal
	principal := PrincipalRef{Kind: PrincipalUser, ID: "u-1"}
	if err := svc.AssignRole(ctx, principal, "role.custom", nil); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	assignments, err := svc.RoleAssignmentsForPrincipal(ctx, principal)
	if err != nil {
		t.Fatalf("RoleAssignmentsForPrincipal failed: %v", err)
	}
	if len(assignments) != 1 || assignments[0].RoleID != "role.custom" {
		t.Errorf("expected assignment to role.custom, got %+v", assignments)
	}

	// Test CreateGrant & GrantsForPrincipal & GrantsForOwners
	customGrant := Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        "u-1",
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "custom.perm",
	}
	if err := svc.CreateGrant(ctx, customGrant); err != nil {
		t.Fatalf("CreateGrant for custom principal failed: %v", err)
	}

	// Create a built-in grant (should go to memory)
	builtInGrant := Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        "builtin.editor",
		Effect:         EffectAllow,
		TeamScope:      "*",
		PermissionName: "builtin.perm",
	}
	if err := svc.CreateGrant(ctx, builtInGrant); err != nil {
		t.Fatalf("CreateGrant for built-in principal failed: %v", err)
	}

	// Fetch via GrantsForPrincipal
	gPrincipal, err := svc.GrantsForPrincipal(ctx, principal)
	if err != nil {
		t.Fatalf("GrantsForPrincipal failed: %v", err)
	}
	if len(gPrincipal) != 1 || gPrincipal[0].PermissionName != "custom.perm" {
		t.Errorf("expected custom.perm grant, got %+v", gPrincipal)
	}

	gBuiltin, err := svc.GrantsForPrincipal(ctx, PrincipalRef{Kind: PrincipalRole, ID: "builtin.editor"})
	if err != nil {
		t.Fatalf("GrantsForPrincipal failed: %v", err)
	}
	// Note: 2 permissions from AddBuiltInRole ("write", "read") + 1 from CreateGrant ("builtin.perm") = 3 grants
	if len(gBuiltin) != 3 {
		t.Errorf("expected 3 grants for built-in role, got %d", len(gBuiltin))
	}

	// Fetch via GrantsForOwners
	owners := []PrincipalRef{principal, {Kind: PrincipalRole, ID: "builtin.editor"}}
	gOwners, err := svc.GrantsForOwners(ctx, owners, Request{})
	if err != nil {
		t.Fatalf("GrantsForOwners failed: %v", err)
	}
	if len(gOwners) != 4 { // 1 custom + 3 built-in
		t.Errorf("expected 4 grants total, got %d", len(gOwners))
	}

	// Test PrincipalsWithGrant
	hits, err := svc.PrincipalsWithGrant(ctx, Request{Perm: "custom.perm"})
	if err != nil {
		t.Fatalf("PrincipalsWithGrant failed: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != "u-1" {
		t.Errorf("expected principal u-1 hit, got %+v", hits)
	}

	// Test ExpandRoles
	// Add custom role inheritance: role.custom inherits builtin.editor
	if err := svc.AddRoleInheritance(ctx, "role.custom", "builtin.editor"); err != nil {
		t.Fatalf("AddRoleInheritance failed: %v", err)
	}
	expanded, err := svc.ExpandRoles(ctx, []string{"role.custom"})
	if err != nil {
		t.Fatalf("ExpandRoles failed: %v", err)
	}
	// Should expand to role.custom and builtin.editor
	expectedRoles := map[string]bool{"role.custom": true, "builtin.editor": true}
	for _, r := range expanded {
		delete(expectedRoles, r)
	}
	if len(expectedRoles) != 0 {
		t.Errorf("ExpandRoles did not return expected roles, remaining: %+v", expectedRoles)
	}

	// Test DeleteGrantsForOwner
	if err := svc.DeleteGrantsForOwner(ctx, PrincipalUser, "u-1"); err != nil {
		t.Fatalf("DeleteGrantsForOwner failed: %v", err)
	}
	gPrincipal2, err := svc.GrantsForPrincipal(ctx, principal)
	if err != nil {
		t.Fatalf("GrantsForPrincipal failed: %v", err)
	}
	if len(gPrincipal2) != 0 {
		t.Errorf("expected 0 grants after delete, got %d", len(gPrincipal2))
	}

	// Deleting built-in grants should fail
	if err := svc.DeleteGrantsForOwner(ctx, PrincipalRole, "builtin.editor"); err == nil {
		t.Error("expected error deleting grants for built-in role")
	}

	// Test DeleteRole for custom role
	if err := svc.DeleteRole(ctx, "role.custom"); err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}
}

func TestRoleDefinitionsByScopeAndTag(t *testing.T) {
	svc := New()
	ctx := context.Background()

	err := svc.AddBuiltInRole(ctx, Role{
		ID:    "builtin.sys-operator",
		Name:  "System Operator",
		Scope: RoleScopeSystem,
		Tags:  []string{"system", "ops"},
	})
	if err != nil {
		t.Fatalf("AddBuiltInRole failed: %v", err)
	}

	err = svc.CreateRole(ctx, Role{
		ID:    "role.team-admin",
		Name:  "Team Admin",
		Scope: RoleScopeTeam,
		Tags:  []string{"team", "admin"},
	})
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	// Test RoleDefinitionsByScope
	sysRoles, err := svc.RoleDefinitionsByScope(ctx, RoleScopeSystem)
	if err != nil {
		t.Fatalf("RoleDefinitionsByScope failed: %v", err)
	}
	foundSys := false
	for _, r := range sysRoles {
		if r.ID == "builtin.sys-operator" {
			foundSys = true
			break
		}
	}
	if !foundSys {
		t.Errorf("expected builtin.sys-operator in system roles")
	}

	teamRoles, err := svc.RoleDefinitionsByScope(ctx, RoleScopeTeam)
	if err != nil {
		t.Fatalf("RoleDefinitionsByScope failed: %v", err)
	}
	foundTeam := false
	for _, r := range teamRoles {
		if r.ID == "role.team-admin" {
			foundTeam = true
			break
		}
	}
	if !foundTeam {
		t.Errorf("expected role.team-admin in team roles")
	}

	// Test RoleDefinitionsByTag
	opsRoles, err := svc.RoleDefinitionsByTag(ctx, "ops")
	if err != nil {
		t.Fatalf("RoleDefinitionsByTag failed: %v", err)
	}
	if len(opsRoles) != 1 || opsRoles[0].ID != "builtin.sys-operator" {
		t.Errorf("expected 1 ops role, got %v", opsRoles)
	}

	adminRoles, err := svc.RoleDefinitionsByTag(ctx, "admin")
	if err != nil {
		t.Fatalf("RoleDefinitionsByTag failed: %v", err)
	}
	if len(adminRoles) != 1 || adminRoles[0].ID != "role.team-admin" {
		t.Errorf("expected 1 admin role, got %v", adminRoles)
	}
}
