package permissions

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type bootstrapStore struct {
	mu                   sync.RWMutex
	roles                map[string]Role
	assignments          map[string][]RoleAssignment
	grants               []Grant
	disabledBuiltInRoles map[string]bool
	// roleInheritance maps parent -> set of direct children.
	roleInheritance map[string]map[string]bool
	// roleClosure maps ancestor -> set of all descendants (transitive).
	// Every role is its own descendant at depth 0.
	roleClosure map[string]map[string]bool
}

func newBootstrapStore() *bootstrapStore {
	return &bootstrapStore{
		roles:                map[string]Role{},
		assignments:          map[string][]RoleAssignment{},
		grants:               []Grant{},
		disabledBuiltInRoles: map[string]bool{},
		roleInheritance:      map[string]map[string]bool{},
		roleClosure:          map[string]map[string]bool{},
	}
}

func (s *bootstrapStore) RoleDefinitions(_ context.Context) ([]Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roles := make([]Role, 0, len(s.roles))
	for _, role := range s.roles {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
	return roles, nil
}

func (s *bootstrapStore) RoleDefinition(_ context.Context, roleID string) (Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, ok := s.roles[roleID]
	if !ok {
		return Role{}, fmt.Errorf("role not found: %s", roleID)
	}
	return role, nil
}

func (s *bootstrapStore) CreateRole(_ context.Context, role Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.ID]; exists {
		return fmt.Errorf("role already exists: %s", role.ID)
	}
	s.roles[role.ID] = role
	// Every role is its own ancestor at depth 0.
	if s.roleClosure[role.ID] == nil {
		s.roleClosure[role.ID] = map[string]bool{}
	}
	s.roleClosure[role.ID][role.ID] = true
	return nil
}

func (s *bootstrapStore) UpdateRole(_ context.Context, role Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.ID]; !exists {
		return fmt.Errorf("role not found: %s", role.ID)
	}
	s.roles[role.ID] = role
	return nil
}

func (s *bootstrapStore) DeleteRole(_ context.Context, roleID string) error {
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[roleID]; !exists {
		return fmt.Errorf("role not found: %s", roleID)
	}
	delete(s.roles, roleID)
	delete(s.roleInheritance, roleID)
	delete(s.roleClosure, roleID)
	for ancestor, descendants := range s.roleClosure {
		delete(descendants, roleID)
		s.roleClosure[ancestor] = descendants
	}
	for parent, children := range s.roleInheritance {
		delete(children, roleID)
		s.roleInheritance[parent] = children
	}
	for key, assignments := range s.assignments {
		filtered := make([]RoleAssignment, 0, len(assignments))
		for _, assignment := range assignments {
			if assignment.RoleID != roleID {
				filtered = append(filtered, assignment)
			}
		}
		s.assignments[key] = filtered
	}
	return nil
}

// AddRoleInheritance adds a parent→child inheritance edge and recomputes the
// full transitive closure so that ExpandRoles returns all inherited descendants.
func (s *bootstrapStore) AddRoleInheritance(_ context.Context, parentRoleID, childRoleID string) error {
	if parentRoleID == "" {
		return fmt.Errorf("parent role ID is required")
	}
	if childRoleID == "" {
		return fmt.Errorf("child role ID is required")
	}
	if parentRoleID == childRoleID {
		return fmt.Errorf("a role cannot inherit itself")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Record direct edge.
	if s.roleInheritance[parentRoleID] == nil {
		s.roleInheritance[parentRoleID] = map[string]bool{}
	}
	if s.roleInheritance[parentRoleID][childRoleID] {
		return nil // already recorded
	}
	s.roleInheritance[parentRoleID][childRoleID] = true

	// Ensure both roles have a self-closure entry.
	if s.roleClosure[parentRoleID] == nil {
		s.roleClosure[parentRoleID] = map[string]bool{parentRoleID: true}
	}
	if s.roleClosure[childRoleID] == nil {
		s.roleClosure[childRoleID] = map[string]bool{childRoleID: true}
	}

	// All descendants of childRoleID are now also descendants of parentRoleID
	// and of every ancestor of parentRoleID.
	// New descendants to add = closure(child).
	newDescendants := s.roleClosure[childRoleID]

	// Collect every ancestor of parentRoleID (roles whose closure contains parentRoleID).
	ancestors := []string{parentRoleID}
	for ancestor, descendants := range s.roleClosure {
		if descendants[parentRoleID] && ancestor != parentRoleID {
			ancestors = append(ancestors, ancestor)
		}
	}

	for _, ancestor := range ancestors {
		for desc := range newDescendants {
			s.roleClosure[ancestor][desc] = true
		}
	}
	return nil
}

func (s *bootstrapStore) RoleAssignmentsForPrincipal(_ context.Context, principal PrincipalRef) ([]RoleAssignment, error) {
	if err := principal.Validate(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	values := s.assignments[principalKey(principal)]
	result := make([]RoleAssignment, 0, len(values))
	for _, assignment := range values {
		copied := RoleAssignment{RoleID: assignment.RoleID, BindingValues: map[string]any{}}
		for k, v := range assignment.BindingValues {
			copied.BindingValues[k] = v
		}
		result = append(result, copied)
	}
	return result, nil
}

func (s *bootstrapStore) AssignRole(_ context.Context, principal PrincipalRef, roleID string, bindingValues map[string]any) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[roleID]; !exists {
		return fmt.Errorf("role not found: %s", roleID)
	}

	assignment := RoleAssignment{RoleID: roleID, BindingValues: map[string]any{}}
	for k, v := range bindingValues {
		assignment.BindingValues[k] = v
	}

	key := principalKey(principal)
	for _, existing := range s.assignments[key] {
		if existing.RoleID == assignment.RoleID && mapEquals(existing.BindingValues, assignment.BindingValues) {
			return nil
		}
	}
	s.assignments[key] = append(s.assignments[key], assignment)
	return nil
}

func (s *bootstrapStore) GrantsForPrincipal(_ context.Context, principal PrincipalRef) ([]Grant, error) {
	if err := principal.Validate(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	grants := make([]Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		if grant.OwnerKind != principal.Kind || grant.OwnerID != principal.ID {
			continue
		}
		if grant.IsExpiredAt(now) {
			continue
		}
		grants = append(grants, cloneGrant(grant))
	}
	return grants, nil
}

func (s *bootstrapStore) GrantsForOwners(_ context.Context, owners []PrincipalRef, req Request) ([]Grant, error) {
	ownerSet := map[string]bool{}
	for _, owner := range owners {
		if err := owner.Validate(); err != nil {
			return nil, err
		}
		ownerSet[principalKey(owner)] = true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	grants := make([]Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		if !ownerSet[principalKey(PrincipalRef{Kind: grant.OwnerKind, ID: grant.OwnerID})] {
			continue
		}
		if grant.IsExpiredAt(now) {
			continue
		}
		if req.Perm != "" && grant.PermissionName != req.Perm {
			continue
		}
		grants = append(grants, cloneGrant(grant))
	}
	return grants, nil
}

func (s *bootstrapStore) CreateGrant(_ context.Context, grant Grant) error {
	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		return fmt.Errorf("team scope is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.grants = append(s.grants, cloneGrant(grant))
	return nil
}

func (s *bootstrapStore) CreateGrants(_ context.Context, grants []Grant) error {
	if len(grants) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, grant := range grants {
		if grant.OwnerID == "" {
			return fmt.Errorf("owner ID is required")
		}
		if grant.PermissionName == "" {
			return fmt.Errorf("permission name is required")
		}
		if grant.TeamScope == "" {
			return fmt.Errorf("team scope is required")
		}
		s.grants = append(s.grants, cloneGrant(grant))
	}

	return nil
}

func (s *bootstrapStore) PrincipalsWithGrant(_ context.Context, req Request) ([]PrincipalHit, error) {
	if req.Perm == "" {
		return nil, fmt.Errorf("permission name is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	denied := map[string]bool{}
	allowed := map[string]PrincipalHit{}

	for _, grant := range s.grants {
		if grant.PermissionName != req.Perm || grant.IsExpiredAt(now) {
			continue
		}
		key := principalKey(PrincipalRef{Kind: grant.OwnerKind, ID: grant.OwnerID})
		if grant.Effect == EffectDeny {
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
		allowed[key] = PrincipalHit{
			Kind:           grant.OwnerKind,
			ID:             grant.OwnerID,
			TeamScope:      grant.TeamScope,
			ObjectScope:    cloneStringPointer(grant.ObjectScope),
			PermissionName: grant.PermissionName,
		}
	}

	results := make([]PrincipalHit, 0, len(allowed))
	for _, hit := range allowed {
		results = append(results, hit)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Kind != results[j].Kind {
			return results[i].Kind < results[j].Kind
		}
		return results[i].ID < results[j].ID
	})
	return results, nil
}

func (s *bootstrapStore) ExpandRoles(_ context.Context, roleIDs []string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := map[string]bool{}
	result := make([]string, 0, len(roleIDs))

	for _, roleID := range roleIDs {
		trimmed := strings.TrimSpace(roleID)
		if trimmed == "" {
			continue
		}
		// Add the role itself.
		if !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
		// Walk the transitive closure.
		for descendant := range s.roleClosure[trimmed] {
			if !seen[descendant] {
				seen[descendant] = true
				result = append(result, descendant)
			}
		}
	}
	return result, nil
}

func principalKey(principal PrincipalRef) string {
	return string(principal.Kind) + ":" + principal.ID
}

func mapEquals(left, right map[string]any) bool {
	if len(left) != len(right) {
		return false
	}
	for k, leftValue := range left {
		rightValue, ok := right[k]
		if !ok || fmt.Sprint(leftValue) != fmt.Sprint(rightValue) {
			return false
		}
	}
	return true
}

func cloneGrant(grant Grant) Grant {
	copyGrant := grant
	copyGrant.ObjectScope = cloneStringPointer(grant.ObjectScope)
	copyGrant.ExpiresAt = cloneTimePointer(grant.ExpiresAt)
	copyGrant.RestrictedFields = append([]string(nil), grant.RestrictedFields...)
	if grant.VariableSpec != nil {
		copyGrant.VariableSpec = map[string]any{}
		for k, v := range grant.VariableSpec {
			copyGrant.VariableSpec[k] = v
		}
	}
	return copyGrant
}

func (s *bootstrapStore) DeleteGrantsForOwner(_ context.Context, ownerKind PrincipalKind, ownerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := make([]Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		if grant.OwnerKind == ownerKind && grant.OwnerID == ownerID {
			continue
		}
		filtered = append(filtered, grant)
	}
	s.grants = filtered
	return nil
}

func (s *bootstrapStore) DisableBuiltInRole(_ context.Context, roleID string) error {
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disabledBuiltInRoles[roleID] = true
	return nil
}

func (s *bootstrapStore) EnableBuiltInRole(_ context.Context, roleID string) error {
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.disabledBuiltInRoles, roleID)
	return nil
}

func (s *bootstrapStore) DisabledBuiltInRoles(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	roles := make([]string, 0, len(s.disabledBuiltInRoles))
	for roleID := range s.disabledBuiltInRoles {
		roles = append(roles, roleID)
	}
	sort.Strings(roles)
	return roles, nil
}

func (s *bootstrapStore) ListGrants(ctx context.Context, query GrantQuery) (GrantQueryResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result GrantQueryResult
	var filtered []Grant

	for _, grant := range s.grants {
		if len(query.Principals) > 0 {
			match := false
			for _, p := range query.Principals {
				if grant.OwnerKind == p.Kind && grant.OwnerID == p.ID {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		if len(query.TeamScopes) > 0 {
			match := false
			for _, ts := range query.TeamScopes {
				if grant.TeamScope == ts {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		if len(query.ObjectScopes) > 0 {
			match := false
			for _, os := range query.ObjectScopes {
				if grant.ObjectScope != nil && *grant.ObjectScope == os {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		if len(query.Permissions) > 0 {
			match := false
			for _, p := range query.Permissions {
				if grant.PermissionName == p {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		if query.PermissionPrefix != "" {
			if !strings.HasPrefix(grant.PermissionName, query.PermissionPrefix) {
				continue
			}
		}

		filtered = append(filtered, grant)
	}

	result.TotalCount = len(filtered)
	offset := 0
	if query.Cursor != "" {
		parsed, err := strconv.Atoi(query.Cursor)
		if err == nil {
			offset = parsed
		}
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 1000 {
		limit = 1000
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	if offset < len(filtered) {
		result.Grants = filtered[offset:end]
	} else {
		result.Grants = []Grant{}
	}
	if end < len(filtered) {
		result.NextCursor = strconv.Itoa(end)
	}

	return result, nil
}
