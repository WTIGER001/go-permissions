package permissions

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type bootstrapStore struct {
	mu          sync.RWMutex
	roles       map[string]Role
	assignments map[string][]RoleAssignment
	grants      []Grant
}

func newBootstrapStore() *bootstrapStore {
	return &bootstrapStore{
		roles:       map[string]Role{},
		assignments: map[string][]RoleAssignment{},
		grants:      []Grant{},
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
	seen := map[string]bool{}
	result := make([]string, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		trimmed := strings.TrimSpace(roleID)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
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
