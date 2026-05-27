package cachedstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/wtiger001/go-permissions"
)

const DefaultTTL = time.Minute

// Store wraps another permissions store and memoizes read operations for a TTL.
// Write operations are delegated and invalidate the cache.
type Store struct {
	base  permissions.PermissionStore
	cache *cache.Cache
	ttl   time.Duration
}

var _ permissions.PermissionStore = (*Store)(nil)

func NewStore(base permissions.PermissionStore) *Store {
	return NewStoreWithTTL(base, DefaultTTL)
}

func NewStoreWithTTL(base permissions.PermissionStore, ttl time.Duration) *Store {
	if base == nil {
		panic("base store is required")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	return &Store{
		base:  base,
		cache: cache.New(ttl, ttl),
		ttl:   ttl,
	}
}

func (s *Store) TTL() time.Duration {
	return s.ttl
}

func (s *Store) InvalidateAll() {
	s.cache.Flush()
}

func (s *Store) RoleDefinitions(ctx context.Context) ([]permissions.Role, error) {
	key := "role-definitions"
	if cachedValue, ok := s.cache.Get(key); ok {
		if v, castOK := cachedValue.([]permissions.Role); castOK {
			cloned := append([]permissions.Role(nil), v...)
			return cloned, nil
		}
	}

	value, err := s.base.RoleDefinitions(ctx)
	if err != nil {
		return nil, err
	}
	cloned := append([]permissions.Role(nil), value...)
	setWithTTL(s.cache, key, cloned, s.ttl)
	return append([]permissions.Role(nil), cloned...), nil
}

func (s *Store) RoleDefinition(ctx context.Context, roleID string) (permissions.Role, error) {
	key := makeKey("role-definition", map[string]any{"role_id": roleID})
	if cachedValue, ok := s.cache.Get(key); ok {
		if v, castOK := cachedValue.(permissions.Role); castOK {
			return v, nil
		}
	}

	value, err := s.base.RoleDefinition(ctx, roleID)
	if err != nil {
		return permissions.Role{}, err
	}
	setWithTTL(s.cache, key, value, s.ttl)
	return value, nil
}

func (s *Store) RoleAssignmentsForPrincipal(ctx context.Context, principal permissions.PrincipalRef) ([]permissions.RoleAssignment, error) {
	key := makeKey("role-assignments-for-principal", map[string]any{"principal": principal})
	if cachedValue, ok := s.cache.Get(key); ok {
		if v, castOK := cachedValue.([]permissions.RoleAssignment); castOK {
			return cloneRoleAssignments(v), nil
		}
	}

	value, err := s.base.RoleAssignmentsForPrincipal(ctx, principal)
	if err != nil {
		return nil, err
	}
	cloned := cloneRoleAssignments(value)
	setWithTTL(s.cache, key, cloned, s.ttl)
	return cloneRoleAssignments(cloned), nil
}

func (s *Store) GrantsForPrincipal(ctx context.Context, principal permissions.PrincipalRef) ([]permissions.Grant, error) {
	key := makeKey("grants-for-principal", map[string]any{"principal": principal})
	if cachedValue, ok := s.cache.Get(key); ok {
		if v, castOK := cachedValue.([]permissions.Grant); castOK {
			return cloneGrants(v), nil
		}
	}

	value, err := s.base.GrantsForPrincipal(ctx, principal)
	if err != nil {
		return nil, err
	}
	cloned := cloneGrants(value)
	setWithTTL(s.cache, key, cloned, s.ttl)
	return cloneGrants(cloned), nil
}

func (s *Store) ExpandRoles(ctx context.Context, roleIDs []string) ([]string, error) {
	key := makeKey("expand-roles", map[string]any{"roles": roleIDs})
	if cachedValue, ok := s.cache.Get(key); ok {
		if v, castOK := cachedValue.([]string); castOK {
			return cloneStrings(v), nil
		}
	}

	value, err := s.base.ExpandRoles(ctx, cloneStrings(roleIDs))
	if err != nil {
		return nil, err
	}
	cloned := cloneStrings(value)
	setWithTTL(s.cache, key, cloned, s.ttl)
	return cloneStrings(cloned), nil
}

func (s *Store) GrantsForOwners(ctx context.Context, owners []permissions.PrincipalRef, req permissions.Request) ([]permissions.Grant, error) {
	key := makeKey("grants-for-owners", map[string]any{"owners": owners, "request": req})
	if cachedValue, ok := s.cache.Get(key); ok {
		if v, castOK := cachedValue.([]permissions.Grant); castOK {
			return cloneGrants(v), nil
		}
	}

	value, err := s.base.GrantsForOwners(ctx, clonePrincipalRefs(owners), req)
	if err != nil {
		return nil, err
	}
	cloned := cloneGrants(value)
	setWithTTL(s.cache, key, cloned, s.ttl)
	return cloneGrants(cloned), nil
}

func (s *Store) PrincipalsWithGrant(ctx context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	key := makeKey("principals-with-grant", map[string]any{"request": req})
	if cachedValue, ok := s.cache.Get(key); ok {
		if v, castOK := cachedValue.([]permissions.PrincipalHit); castOK {
			return clonePrincipalHits(v), nil
		}
	}

	value, err := s.base.PrincipalsWithGrant(ctx, req)
	if err != nil {
		return nil, err
	}
	cloned := clonePrincipalHits(value)
	setWithTTL(s.cache, key, cloned, s.ttl)
	return clonePrincipalHits(cloned), nil
}

func (s *Store) CreateGrant(ctx context.Context, grant permissions.Grant) error {
	writer, ok := s.base.(permissions.GrantWriter)
	if !ok {
		return fmt.Errorf("base store does not support grant writes")
	}
	if err := writer.CreateGrant(ctx, grant); err != nil {
		return err
	}
	s.InvalidateAll()
	return nil
}

func (s *Store) AssignRole(ctx context.Context, principal permissions.PrincipalRef, roleID string, bindingValues map[string]any) error {
	writer, ok := s.base.(permissions.RoleAssignmentWriter)
	if !ok {
		return fmt.Errorf("base store does not support role assignment writes")
	}
	if err := writer.AssignRole(ctx, principal, roleID, cloneMap(bindingValues)); err != nil {
		return err
	}
	s.InvalidateAll()
	return nil
}

func makeKey(prefix string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return prefix
	}
	return prefix + ":" + string(encoded)
}

func setWithTTL(c *cache.Cache, key string, value any, ttl time.Duration) {
	c.Set(key, value, ttl)
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func clonePrincipalRefs(values []permissions.PrincipalRef) []permissions.PrincipalRef {
	if len(values) == 0 {
		return nil
	}
	result := make([]permissions.PrincipalRef, len(values))
	copy(result, values)
	return result
}

func cloneRoleAssignments(values []permissions.RoleAssignment) []permissions.RoleAssignment {
	if len(values) == 0 {
		return nil
	}
	result := make([]permissions.RoleAssignment, 0, len(values))
	for _, assignment := range values {
		copied := permissions.RoleAssignment{RoleID: assignment.RoleID, BindingValues: cloneMap(assignment.BindingValues)}
		result = append(result, copied)
	}
	return result
}

func cloneGrants(values []permissions.Grant) []permissions.Grant {
	if len(values) == 0 {
		return nil
	}
	result := make([]permissions.Grant, 0, len(values))
	for _, grant := range values {
		copied := grant
		copied.ObjectScope = cloneStringPtr(grant.ObjectScope)
		copied.ExpiresAt = cloneTimePtr(grant.ExpiresAt)
		copied.FieldAllowlist = append([]string(nil), grant.FieldAllowlist...)
		copied.VariableSpec = cloneMap(grant.VariableSpec)
		result = append(result, copied)
	}
	return result
}

func clonePrincipalHits(values []permissions.PrincipalHit) []permissions.PrincipalHit {
	if len(values) == 0 {
		return nil
	}
	result := make([]permissions.PrincipalHit, 0, len(values))
	for _, hit := range values {
		copied := hit
		copied.ObjectScope = cloneStringPtr(hit.ObjectScope)
		result = append(result, copied)
	}
	return result
}

func cloneStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	copied := *v
	return &copied
}

func cloneTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	copied := *v
	return &copied
}

func cloneMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return map[string]any{}
	}
	result := make(map[string]any, len(values))
	for k, v := range values {
		result[k] = v
	}
	return result
}
