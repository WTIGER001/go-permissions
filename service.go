package permissions

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	identity            IdentityProvider
	permissions         PermissionStore
	builtInGrants       []Grant
	publicRoleID        string
	authenticatedRoleID string
	adminRoleID         string
	adminGroupID        string
}

// New creates a service with a nil identity provider and an in-memory default store.
func New() *Service {
	return &Service{permissions: newBootstrapStore()}
}

// NewService wires the service to a permission store and identity provider.
func NewService(permissionStore PermissionStore, identityProvider IdentityProvider) *Service {
	if permissionStore == nil {
		permissionStore = newBootstrapStore()
	}
	return &Service{
		identity:    identityProvider,
		permissions: permissionStore,
	}
}

// SetIdentityProvider updates the identity provider used by permission checks.
func (s *Service) SetIdentityProvider(identity IdentityProvider) {
	s.identity = identity
}

// SetStore updates the permission store and immediately re-runs built-in seeding.
func (s *Service) SetStore(store PermissionStore) error {
	if store == nil {
		store = newBootstrapStore()
	}
	s.permissions = store

	return s.SaveBuiltIns(context.Background(), s.builtInGrants)
}

// SetBuiltInGrants configures built-in grants used by SaveBuiltIns and SetStore bootstrap.
func (s *Service) SetBuiltInGrants(grants []Grant) {
	s.builtInGrants = cloneGrantSlice(grants)
}

// SetPublicRoleID configures the synthetic role applied to anonymous requests.
func (s *Service) SetPublicRoleID(roleID string) {
	s.publicRoleID = strings.TrimSpace(roleID)
}

// SetAuthenticatedRoleID configures the synthetic role applied to authenticated requests.
func (s *Service) SetAuthenticatedRoleID(roleID string) {
	s.authenticatedRoleID = strings.TrimSpace(roleID)
}

// SetAdminRoleID configures the synthetic role applied to users in the configured admin group.
func (s *Service) SetAdminRoleID(roleID string) {
	s.adminRoleID = strings.TrimSpace(roleID)
}

// SetAdminGroupID configures which group grants the synthetic admin role.
func (s *Service) SetAdminGroupID(groupID string) {
	s.adminGroupID = strings.TrimSpace(groupID)
}

// SetSyntheticRoleIDs configures all synthetic role IDs at once.
func (s *Service) SetSyntheticRoleIDs(publicRoleID, authenticatedRoleID, adminRoleID string) {
	s.publicRoleID = strings.TrimSpace(publicRoleID)
	s.authenticatedRoleID = strings.TrimSpace(authenticatedRoleID)
	s.adminRoleID = strings.TrimSpace(adminRoleID)
}

// NewServiceWithProviders is an alias for NewService.
func NewServiceWithProviders(permissionStore PermissionStore, identityProvider IdentityProvider) *Service {
	return NewService(permissionStore, identityProvider)
}

// NewServiceWithIdentity wires a custom identity provider with a permission store.
// This is the recommended constructor when users/groups/memberships are managed externally.
func NewServiceWithIdentity(identity IdentityProvider, permissionStore PermissionStore) *Service {
	return NewService(permissionStore, identity)
}

func (s *Service) AllowUser(ctx context.Context, userID, permission string, objectID *string) error {
	return s.createGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
	})
}

func (s *Service) AllowUserUntil(ctx context.Context, userID, permission string, objectID *string, expiresAt time.Time) error {
	return s.createGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
		ExpiresAt:      cloneTimePointer(&expiresAt),
	})
}

func (s *Service) AllowUserFor(ctx context.Context, userID, permission string, objectID *string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl must be greater than zero")
	}
	return s.AllowUserUntil(ctx, userID, permission, objectID, time.Now().UTC().Add(ttl))
}

func (s *Service) DenyUser(ctx context.Context, userID, permission string, objectID *string) error {
	return s.createGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectDeny,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
	})
}

func (s *Service) DenyUserUntil(ctx context.Context, userID, permission string, objectID *string, expiresAt time.Time) error {
	return s.createGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectDeny,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
		ExpiresAt:      cloneTimePointer(&expiresAt),
	})
}

func (s *Service) DenyUserFor(ctx context.Context, userID, permission string, objectID *string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl must be greater than zero")
	}
	return s.DenyUserUntil(ctx, userID, permission, objectID, time.Now().UTC().Add(ttl))
}

func (s *Service) AllowRole(ctx context.Context, roleID, permission string, objectID *string) error {
	return s.createGrant(ctx, Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        roleID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
	})
}

func (s *Service) AllowRoleUntil(ctx context.Context, roleID, permission string, objectID *string, expiresAt time.Time) error {
	return s.createGrant(ctx, Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        roleID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
		ExpiresAt:      cloneTimePointer(&expiresAt),
	})
}

func (s *Service) AllowRoleFor(ctx context.Context, roleID, permission string, objectID *string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl must be greater than zero")
	}
	return s.AllowRoleUntil(ctx, roleID, permission, objectID, time.Now().UTC().Add(ttl))
}

func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleID string, bindingValues map[string]any) error {
	if userID == "" {
		return fmt.Errorf("user ID is required")
	}
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	copyBinding := map[string]any{}
	for k, v := range bindingValues {
		copyBinding[k] = v
	}

	return s.permissions.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: userID}, roleID, copyBinding)
}

func (s *Service) HasSystemPermission(ctx context.Context, userID string, perm string) (bool, error) {
	return s.HasPermission(ctx, Request{UserID: userID, Perm: perm})
}

func (s *Service) HasTeamPermission(ctx context.Context, userID string, teamID int64, object, perm string) (bool, error) {
	return s.HasPermission(ctx, Request{UserID: userID, TeamID: &teamID, Object: object, Perm: perm})
}

func (s *Service) HasFieldPermission(ctx context.Context, req Request, fieldPath string) (bool, error) {
	if isIndexedFieldPath(fieldPath) {
		return false, fmt.Errorf("indexed field paths are not supported: %q", fieldPath)
	}
	if strings.TrimSpace(fieldPath) == "" {
		return false, fmt.Errorf("field path is required")
	}

	return s.evaluatePermission(ctx, req, &fieldPath)
}

func (s *Service) FilterPermittedFields(ctx context.Context, req Request, fieldPaths []string) ([]string, error) {
	result := make([]string, 0, len(fieldPaths))
	seen := make(map[string]bool, len(fieldPaths))

	for _, path := range fieldPaths {
		if seen[path] {
			continue
		}
		seen[path] = true

		allowed, err := s.HasFieldPermission(ctx, req, path)
		if err != nil {
			return nil, err
		}
		if allowed {
			result = append(result, path)
		}
	}

	return result, nil
}

func (s *Service) HasPermission(ctx context.Context, req Request) (bool, error) {
	return s.evaluatePermission(ctx, req, nil)
}

func (s *Service) evaluatePermission(ctx context.Context, req Request, fieldPath *string) (bool, error) {
	if req.TeamID != nil && *req.TeamID <= 0 {
		return false, fmt.Errorf("team ID must be positive when provided")
	}
	if req.Perm == "" {
		return false, fmt.Errorf("permission name is required")
	}

	now := time.Now().UTC()

	groupIDs, err := s.resolveUserGroupIDs(ctx, req.UserID)
	if err != nil {
		return false, err
	}

	roleAssignments, err := s.resolveRoleAssignmentsForUserAndGroups(ctx, req.UserID, groupIDs)
	if err != nil {
		return false, err
	}

	bindingByRoleID := make(map[string]map[string]any, len(roleAssignments))

	directRoleIDs := make([]string, 0, len(roleAssignments))
	for _, assignment := range roleAssignments {
		directRoleIDs = append(directRoleIDs, assignment.RoleID)
		bindingByRoleID[assignment.RoleID] = assignment.BindingValues
	}

	roleIDs, err := s.permissions.ExpandRoles(ctx, directRoleIDs)
	if err != nil {
		return false, err
	}

	owners := make([]PrincipalRef, 0, 1+len(groupIDs)+len(roleIDs))
	if req.UserID != "" {
		owners = append(owners, PrincipalRef{Kind: PrincipalUser, ID: req.UserID})
	}
	for _, groupID := range groupIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
	}
	for _, roleID := range roleIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalRole, ID: roleID})
	}

	grants, err := s.permissions.GrantsForOwners(ctx, owners, req)
	if err != nil {
		return false, err
	}

	allowed := false
	for _, grant := range grants {
		if grant.IsExpiredAt(now) {
			continue
		}
		resolvedGrant, err := resolveGrantBindings(grant, bindingByRoleID)
		if err != nil {
			return false, err
		}

		if !grantMatchesRequest(resolvedGrant, req) {
			continue
		}

		if !grantMatchesFieldPath(resolvedGrant, fieldPath) {
			continue
		}

		if resolvedGrant.Effect == EffectDeny {
			if fieldPath == nil && len(resolvedGrant.RestrictedFields) > 0 {
				// Field-scoped deny does not deny the entire permission check.
				continue
			}
			return false, nil
		}
		allowed = true
	}

	return allowed, nil
}

func (s *Service) EffectivePermissions(ctx context.Context, userID string, teamID *int64) ([]EffectivePermission, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}
	if teamID != nil && *teamID <= 0 {
		return nil, fmt.Errorf("team ID must be positive when provided")
	}

	now := time.Now().UTC()

	groupIDs, err := s.resolveUserGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}

	roleAssignments, err := s.resolveRoleAssignmentsForUserAndGroups(ctx, userID, groupIDs)
	if err != nil {
		return nil, err
	}

	bindingByRoleID := make(map[string]map[string]any, len(roleAssignments))
	directRoleIDs := make([]string, 0, len(roleAssignments))
	for _, assignment := range roleAssignments {
		directRoleIDs = append(directRoleIDs, assignment.RoleID)
		bindingByRoleID[assignment.RoleID] = assignment.BindingValues
	}

	expandedRoleIDs, err := s.permissions.ExpandRoles(ctx, directRoleIDs)
	if err != nil {
		return nil, err
	}

	owners := make([]PrincipalRef, 0, 1+len(groupIDs)+len(expandedRoleIDs))
	owners = append(owners, PrincipalRef{Kind: PrincipalUser, ID: userID})
	for _, groupID := range groupIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
	}
	for _, roleID := range expandedRoleIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalRole, ID: roleID})
	}

	grants, err := s.permissions.GrantsForOwners(ctx, owners, Request{UserID: userID, TeamID: teamID})
	if err != nil {
		return nil, err
	}

	denied := map[string]bool{}
	allowed := map[string]EffectivePermission{}

	for _, grant := range grants {
		if grant.IsExpiredAt(now) {
			continue
		}
		resolvedGrant, err := resolveGrantBindings(grant, bindingByRoleID)
		if err != nil {
			return nil, err
		}

		if !matchesTeamScope(resolvedGrant, teamID) {
			continue
		}

		key := permissionKey(resolvedGrant)
		if resolvedGrant.Effect == EffectDeny {
			denied[key] = true
			delete(allowed, key)
			continue
		}

		if denied[key] {
			continue
		}

		if _, exists := allowed[key]; exists {
			continue
		}

		allowed[key] = EffectivePermission{
			TeamScope:      resolvedGrant.TeamScope,
			ObjectScope:    resolvedGrant.ObjectScope,
			PermissionName: resolvedGrant.PermissionName,
			Source: PrincipalRef{
				Kind: resolvedGrant.OwnerKind,
				ID:   resolvedGrant.OwnerID,
			},
			Effect:           resolvedGrant.Effect,
			RestrictedFields: append([]string(nil), resolvedGrant.RestrictedFields...),
		}
	}

	result := make([]EffectivePermission, 0, len(allowed))
	for _, eff := range allowed {
		result = append(result, eff)
	}

	return result, nil
}

func (s *Service) PrincipalsWithPermission(ctx context.Context, teamID *int64, object, perm string) ([]PrincipalHit, error) {
	if teamID != nil && *teamID <= 0 {
		return nil, fmt.Errorf("team ID must be positive when provided")
	}
	if perm == "" {
		return nil, fmt.Errorf("permission name is required")
	}

	hits, err := s.permissions.PrincipalsWithGrant(ctx, Request{
		TeamID: teamID,
		Object: object,
		Perm:   perm,
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Kind != hits[j].Kind {
			return hits[i].Kind < hits[j].Kind
		}
		if hits[i].ID != hits[j].ID {
			return hits[i].ID < hits[j].ID
		}
		if hits[i].TeamScope != hits[j].TeamScope {
			return hits[i].TeamScope < hits[j].TeamScope
		}

		left := ""
		right := ""
		if hits[i].ObjectScope != nil {
			left = *hits[i].ObjectScope
		}
		if hits[j].ObjectScope != nil {
			right = *hits[j].ObjectScope
		}

		return left < right
	})

	return hits, nil
}

func grantMatchesRequest(grant Grant, req Request) bool {
	if grant.PermissionName != req.Perm {
		return false
	}

	if !matchesTeamScope(grant, req.TeamID) {
		return false
	}

	if grant.ObjectScope == nil {
		return true
	}

	objectScope := *grant.ObjectScope
	if objectScope == "*" {
		return true
	}

	return objectScope == req.Object
}

func grantMatchesFieldPath(grant Grant, fieldPath *string) bool {
	if fieldPath == nil {
		return true
	}

	if len(grant.RestrictedFields) == 0 {
		return true
	}

	matchesRestricted := false
	for _, restrictedPath := range grant.RestrictedFields {
		if fieldPathMatches(restrictedPath, *fieldPath) {
			matchesRestricted = true
			break
		}
	}

	if grant.Effect == EffectDeny {
		return matchesRestricted
	}

	return !matchesRestricted
}

func fieldPathMatches(grantPath, candidate string) bool {
	grantPath = strings.TrimSpace(grantPath)
	candidate = strings.TrimSpace(candidate)
	if grantPath == "" || candidate == "" {
		return false
	}
	if grantPath == candidate {
		return true
	}

	return strings.HasPrefix(candidate, grantPath+".")
}

func isIndexedFieldPath(path string) bool {
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		allDigits := true
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}

	return false
}

func matchesTeamScope(grant Grant, teamID *int64) bool {
	if teamID == nil {
		return grant.TeamScope == "*"
	}

	team := strconv.FormatInt(*teamID, 10)
	return grant.TeamScope == "*" || grant.TeamScope == team
}

func permissionKey(grant Grant) string {
	obj := ""
	if grant.ObjectScope != nil {
		obj = *grant.ObjectScope
	}
	return strings.Join([]string{grant.TeamScope, obj, grant.PermissionName}, "::")
}

func resolveGrantBindings(grant Grant, bindingByRoleID map[string]map[string]any) (Grant, error) {
	if len(grant.VariableSpec) == 0 {
		return grant, nil
	}

	bindingValues := map[string]any{}
	if grant.OwnerKind == PrincipalRole {
		var ok bool
		bindingValues, ok = bindingByRoleID[grant.OwnerID]
		if !ok {
			return Grant{}, fmt.Errorf("missing role binding for role ID %q", grant.OwnerID)
		}
	}

	for key, spec := range grant.VariableSpec {
		required, ok := spec.(string)
		if !ok {
			continue
		}
		if required == "required" {
			if _, exists := bindingValues[key]; !exists {
				return Grant{}, fmt.Errorf("missing required binding value %q for role ID %q", key, grant.OwnerID)
			}
		}
	}

	teamScope, err := resolveScopeToken(grant.TeamScope, bindingValues)
	if err != nil {
		return Grant{}, err
	}
	grant.TeamScope = teamScope

	if grant.ObjectScope != nil {
		resolved, err := resolveScopeToken(*grant.ObjectScope, bindingValues)
		if err != nil {
			return Grant{}, err
		}
		grant.ObjectScope = &resolved
	}

	return grant, nil
}

func resolveScopeToken(scope string, bindingValues map[string]any) (string, error) {
	if !strings.HasPrefix(scope, "?") {
		return scope, nil
	}

	name := strings.TrimPrefix(scope, "?")
	value, ok := bindingValues[name]
	if !ok {
		return "", fmt.Errorf("missing binding value for token %q", name)
	}

	switch typed := value.(type) {
	case string:
		return typed, nil
	case int:
		return strconv.Itoa(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case float64:
		return strconv.FormatInt(int64(typed), 10), nil
	default:
		return fmt.Sprintf("%v", value), nil
	}
}

func (s *Service) resolveUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	if userID == "" {
		return nil, nil
	}
	if s.identity == nil {
		return nil, nil
	}

	groupIDs, err := s.identity.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(groupIDs))
	seen := map[string]bool{}
	for _, groupID := range groupIDs {
		if seen[groupID] {
			continue
		}
		seen[groupID] = true
		result = append(result, groupID)
	}

	return result, nil
}

func (s *Service) resolveRoleAssignmentsForUserAndGroups(ctx context.Context, userID string, groupIDs []string) ([]RoleAssignment, error) {
	result := []RoleAssignment{}
	seenRoleIDs := map[string]bool{}
	appendUnique := func(assignments []RoleAssignment) {
		for _, assignment := range assignments {
			if assignment.RoleID == "" || seenRoleIDs[assignment.RoleID] {
				continue
			}
			seenRoleIDs[assignment.RoleID] = true
			if assignment.BindingValues == nil {
				assignment.BindingValues = map[string]any{}
			}
			result = append(result, assignment)
		}
	}

	if userID != "" {
		userAssignments, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: userID})
		if err != nil {
			return nil, err
		}
		appendUnique(userAssignments)
	}

	for _, groupID := range groupIDs {
		groupAssignments, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
		if err != nil {
			return nil, err
		}
		appendUnique(groupAssignments)
	}

	appendUnique(s.syntheticRoleAssignments(userID, groupIDs))

	return result, nil
}

func (s *Service) syntheticRoleAssignments(userID string, groupIDs []string) []RoleAssignment {
	assignments := make([]RoleAssignment, 0, 3)

	if s.publicRoleID != "" {
		assignments = append(assignments, RoleAssignment{RoleID: s.publicRoleID, BindingValues: map[string]any{}})
	}

	if userID != "" && s.authenticatedRoleID != "" {
		assignments = append(assignments, RoleAssignment{RoleID: s.authenticatedRoleID, BindingValues: map[string]any{}})
	}

	if userID != "" && s.adminRoleID != "" && s.adminGroupID != "" && containsString(groupIDs, s.adminGroupID) {
		assignments = append(assignments, RoleAssignment{RoleID: s.adminRoleID, BindingValues: map[string]any{}})
	}

	return assignments
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func (s *Service) createGrant(ctx context.Context, grant Grant) error {
	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		return fmt.Errorf("team scope is required")
	}

	return s.permissions.CreateGrant(ctx, grant)
}

// EnsureSyntheticRoles ensures configured synthetic roles exist without overwriting existing definitions.
func (s *Service) EnsureSyntheticRoles(ctx context.Context) error {
	roles := []Role{}
	if s.publicRoleID != "" {
		roles = append(roles, Role{ID: s.publicRoleID, Name: s.publicRoleID, Description: "synthetic public role"})
	}
	if s.authenticatedRoleID != "" {
		roles = append(roles, Role{ID: s.authenticatedRoleID, Name: s.authenticatedRoleID, Description: "synthetic authenticated role"})
	}
	if s.adminRoleID != "" {
		roles = append(roles, Role{ID: s.adminRoleID, Name: s.adminRoleID, Description: "synthetic admin role"})
	}

	seen := map[string]bool{}
	for _, role := range roles {
		if role.ID == "" || seen[role.ID] {
			continue
		}
		seen[role.ID] = true
		if err := s.ensureRoleExists(ctx, role); err != nil {
			return err
		}
	}

	return nil
}

// EnsureGrantForOwner creates a grant only when an equivalent active grant does not already exist.
// This keeps startup/bootstrap flows idempotent across store implementations.
func (s *Service) EnsureGrantForOwner(ctx context.Context, grant Grant) error {
	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		return fmt.Errorf("team scope is required")
	}

	principal := PrincipalRef{Kind: grant.OwnerKind, ID: grant.OwnerID}
	if err := principal.Validate(); err != nil {
		return err
	}

	existing, err := s.permissions.GrantsForPrincipal(ctx, principal)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, current := range existing {
		if current.IsExpiredAt(now) {
			continue
		}
		if grantsEquivalent(current, grant) {
			return nil
		}
	}

	return s.permissions.CreateGrant(ctx, grant)
}

// SaveBuiltIns performs idempotent startup seeding for configured synthetic roles and grants.
// It creates missing synthetic roles and then ensures each synthetic grant exists once.
func (s *Service) SaveBuiltIns(ctx context.Context, grants []Grant) error {
	if err := s.EnsureSyntheticRoles(ctx); err != nil {
		return err
	}

	allowedRoleIDs := s.syntheticRoleIDSet()
	for _, grant := range grants {
		if grant.OwnerKind != PrincipalRole {
			return fmt.Errorf("save built-ins only supports role-owned grants")
		}
		if !allowedRoleIDs[grant.OwnerID] {
			return fmt.Errorf("grant owner %q is not a configured synthetic role", grant.OwnerID)
		}
		if err := s.EnsureGrantForOwner(ctx, grant); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) syntheticRoleIDSet() map[string]bool {
	set := map[string]bool{}
	if s.publicRoleID != "" {
		set[s.publicRoleID] = true
	}
	if s.authenticatedRoleID != "" {
		set[s.authenticatedRoleID] = true
	}
	if s.adminRoleID != "" {
		set[s.adminRoleID] = true
	}

	return set
}

func (s *Service) ensureRoleExists(ctx context.Context, role Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	existing, err := s.permissions.RoleDefinition(ctx, role.ID)
	if err == nil && existing.ID == role.ID {
		return nil
	}

	if err := s.permissions.CreateRole(ctx, role); err != nil {
		// Another writer may have created it in parallel; confirm presence and treat as success.
		confirm, confirmErr := s.permissions.RoleDefinition(ctx, role.ID)
		if confirmErr == nil && confirm.ID == role.ID {
			return nil
		}
		return err
	}

	return nil
}

func grantsEquivalent(left, right Grant) bool {
	if left.OwnerKind != right.OwnerKind || left.OwnerID != right.OwnerID {
		return false
	}
	if left.Effect != right.Effect || left.TeamScope != right.TeamScope || left.PermissionName != right.PermissionName {
		return false
	}
	if !sameStringPointer(left.ObjectScope, right.ObjectScope) {
		return false
	}
	if !sameTimePointer(left.ExpiresAt, right.ExpiresAt) {
		return false
	}
	if !sameStringSet(left.RestrictedFields, right.RestrictedFields) {
		return false
	}

	return reflect.DeepEqual(left.VariableSpec, right.VariableSpec)
}

func sameStringPointer(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return *left == *right
}

func sameTimePointer(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Equal(*right)
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	if len(left) == 0 {
		return true
	}

	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)

	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}

	return true
}

func cloneGrantSlice(values []Grant) []Grant {
	if len(values) == 0 {
		return nil
	}

	cloned := make([]Grant, 0, len(values))
	for _, grant := range values {
		copyGrant := grant
		copyGrant.ObjectScope = cloneStringPointer(grant.ObjectScope)
		copyGrant.ExpiresAt = cloneTimePointer(grant.ExpiresAt)
		copyGrant.RestrictedFields = append([]string(nil), grant.RestrictedFields...)
		if grant.VariableSpec != nil {
			copyGrant.VariableSpec = map[string]any{}
			for k, v := range grant.VariableSpec {
				copyGrant.VariableSpec[k] = v
			}
		} else {
			copyGrant.VariableSpec = nil
		}
		cloned = append(cloned, copyGrant)
	}

	return cloned
}

func cloneStringPointer(v *string) *string {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}

func cloneTimePointer(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}
