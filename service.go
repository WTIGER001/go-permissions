package permissions

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	identity    IdentityProvider
	permissions PermissionStore
}

// NewService wires the service to a permission store and identity provider.
func NewService(permissionStore PermissionStore, identityProvider IdentityProvider) *Service {
	return &Service{identity: identityProvider, permissions: permissionStore}
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
	writer, ok := s.permissions.(RoleAssignmentWriter)
	if !ok {
		return fmt.Errorf("permission store does not support role assignment writes")
	}

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

	return writer.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: userID}, roleID, copyBinding)
}

func (s *Service) HasSystemPermission(ctx context.Context, userID string, perm string) (bool, error) {
	return s.HasPermission(ctx, Request{UserID: userID, Perm: perm})
}

func (s *Service) HasTeamPermission(ctx context.Context, userID string, teamID int64, object, perm string) (bool, error) {
	return s.HasPermission(ctx, Request{UserID: userID, TeamID: &teamID, Object: object, Perm: perm})
}

func (s *Service) HasPermission(ctx context.Context, req Request) (bool, error) {
	if req.UserID == "" {
		return false, fmt.Errorf("user ID is required")
	}
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
	owners = append(owners, PrincipalRef{Kind: PrincipalUser, ID: req.UserID})
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
		if resolvedGrant.Effect == EffectDeny {
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
			Effect: resolvedGrant.Effect,
			Fields: append([]string(nil), resolvedGrant.FieldAllowlist...),
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
	result, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: userID})
	if err != nil {
		return nil, err
	}

	for _, groupID := range groupIDs {
		groupAssignments, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
		if err != nil {
			return nil, err
		}
		result = append(result, groupAssignments...)
	}

	return result, nil
}

func (s *Service) createGrant(ctx context.Context, grant Grant) error {
	writer, ok := s.permissions.(GrantWriter)
	if !ok {
		return fmt.Errorf("permission store does not support grant writes")
	}

	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		return fmt.Errorf("team scope is required")
	}

	return writer.CreateGrant(ctx, grant)
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
