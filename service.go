package permissions

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Service struct {
	identity IdentityResolver
	policy   PolicyStore
}

func NewService(store Store) *Service {
	return &Service{identity: store, policy: store}
}

// NewServiceWithIdentity wires a custom identity resolver with a policy store.
// This is the recommended constructor when users/groups/memberships are managed externally.
func NewServiceWithIdentity(identity IdentityResolver, policy PolicyStore) *Service {
	return &Service{identity: identity, policy: policy}
}

func NewServiceWithResolvers(identity IdentityResolver, policy PolicyStore) *Service {
	return NewServiceWithIdentity(identity, policy)
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

func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleID string, bindingValues map[string]any) error {
	writer, ok := s.policy.(RoleAssignmentWriter)
	if !ok {
		return fmt.Errorf("policy store does not support role assignment writes")
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

	groupIDs, err := s.resolveUserGroupIDs(ctx, req.UserID)
	if err != nil {
		return false, err
	}

	roleAssignments, err := s.policy.ListRoleAssignmentsForUserAndGroups(ctx, req.UserID, groupIDs)
	if err != nil {
		return false, err
	}

	bindingByRoleID := make(map[string]map[string]any, len(roleAssignments))

	directRoleIDs := make([]string, 0, len(roleAssignments))
	for _, assignment := range roleAssignments {
		directRoleIDs = append(directRoleIDs, assignment.RoleID)
		bindingByRoleID[assignment.RoleID] = assignment.BindingValues
	}

	roleIDs, err := s.policy.ListExpandedRoleIDs(ctx, directRoleIDs)
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

	grants, err := s.policy.ListGrantsForOwners(ctx, owners, req)
	if err != nil {
		return false, err
	}

	allowed := false
	for _, grant := range grants {
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

	groupIDs, err := s.resolveUserGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}

	roleAssignments, err := s.policy.ListRoleAssignmentsForUserAndGroups(ctx, userID, groupIDs)
	if err != nil {
		return nil, err
	}

	bindingByRoleID := make(map[string]map[string]any, len(roleAssignments))
	directRoleIDs := make([]string, 0, len(roleAssignments))
	for _, assignment := range roleAssignments {
		directRoleIDs = append(directRoleIDs, assignment.RoleID)
		bindingByRoleID[assignment.RoleID] = assignment.BindingValues
	}

	expandedRoleIDs, err := s.policy.ListExpandedRoleIDs(ctx, directRoleIDs)
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

	grants, err := s.policy.ListGrantsForOwners(ctx, owners, Request{UserID: userID, TeamID: teamID})
	if err != nil {
		return nil, err
	}

	denied := map[string]bool{}
	allowed := map[string]EffectivePermission{}

	for _, grant := range grants {
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

	hits, err := s.policy.ListPrincipalsWithGrant(ctx, Request{
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
	candidateGroupIDs, err := s.policy.ListKnownGroupIDs(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(candidateGroupIDs))
	seen := map[string]bool{}
	for _, groupID := range candidateGroupIDs {
		if seen[groupID] {
			continue
		}
		ok, err := s.identity.IsUserInGroup(ctx, userID, groupID)
		if err != nil {
			return nil, err
		}
		if ok {
			seen[groupID] = true
			result = append(result, groupID)
		}
	}

	return result, nil
}

func (s *Service) createGrant(ctx context.Context, grant Grant) error {
	writer, ok := s.policy.(GrantWriter)
	if !ok {
		return fmt.Errorf("policy store does not support grant writes")
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
