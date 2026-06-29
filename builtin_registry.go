package permissions

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const BuiltInPrefix = "builtin."

type builtInRegistry struct {
	mu              sync.RWMutex
	roles           map[string]Role
	grants          []Grant
	roleInheritance map[string]map[string]bool
	roleClosure     map[string]map[string]bool
}

func newBuiltInRegistry() *builtInRegistry {
	return &builtInRegistry{
		roles:           map[string]Role{},
		grants:          []Grant{},
		roleInheritance: map[string]map[string]bool{},
		roleClosure:     map[string]map[string]bool{},
	}
}

func (r *builtInRegistry) RegisterRole(role Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if !strings.HasPrefix(role.ID, BuiltInPrefix) {
		return fmt.Errorf("built-in role ID must start with %q, got %q", BuiltInPrefix, role.ID)
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	role.BuiltIn = true

	r.mu.Lock()
	defer r.mu.Unlock()

	r.roles[role.ID] = role
	if r.roleClosure[role.ID] == nil {
		r.roleClosure[role.ID] = map[string]bool{}
	}
	r.roleClosure[role.ID][role.ID] = true
	return nil
}

func (r *builtInRegistry) Role(roleID string) (Role, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, ok := r.roles[roleID]
	return role, ok
}

func (r *builtInRegistry) Roles() []Role {
	r.mu.RLock()
	defer r.mu.RUnlock()

	roles := make([]Role, 0, len(r.roles))
	for _, role := range r.roles {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
	return roles
}

func (r *builtInRegistry) AddRoleInheritance(parentRoleID, childRoleID string) error {
	if parentRoleID == "" || childRoleID == "" {
		return fmt.Errorf("parent and child role IDs are required")
	}
	if !strings.HasPrefix(parentRoleID, BuiltInPrefix) {
		return fmt.Errorf("parent role ID must start with %q, got %q", BuiltInPrefix, parentRoleID)
	}
	if !strings.HasPrefix(childRoleID, BuiltInPrefix) {
		return fmt.Errorf("child role ID must start with %q, got %q", BuiltInPrefix, childRoleID)
	}
	if parentRoleID == childRoleID {
		return fmt.Errorf("a role cannot inherit itself")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.roleInheritance[parentRoleID] == nil {
		r.roleInheritance[parentRoleID] = map[string]bool{}
	}
	if r.roleInheritance[parentRoleID][childRoleID] {
		return nil
	}
	r.roleInheritance[parentRoleID][childRoleID] = true

	if r.roleClosure[parentRoleID] == nil {
		r.roleClosure[parentRoleID] = map[string]bool{parentRoleID: true}
	}
	if r.roleClosure[childRoleID] == nil {
		r.roleClosure[childRoleID] = map[string]bool{childRoleID: true}
	}

	newDescendants := r.roleClosure[childRoleID]
	ancestors := []string{parentRoleID}
	for ancestor, descendants := range r.roleClosure {
		if descendants[parentRoleID] && ancestor != parentRoleID {
			ancestors = append(ancestors, ancestor)
		}
	}

	for _, ancestor := range ancestors {
		for desc := range newDescendants {
			r.roleClosure[ancestor][desc] = true
		}
	}
	return nil
}

func (r *builtInRegistry) ExpandRoles(roleIDs []string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := map[string]bool{}
	result := make([]string, 0, len(roleIDs))

	for _, roleID := range roleIDs {
		trimmed := strings.TrimSpace(roleID)
		if trimmed == "" {
			continue
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
		for descendant := range r.roleClosure[trimmed] {
			if !seen[descendant] {
				seen[descendant] = true
				result = append(result, descendant)
			}
		}
	}
	return result
}

func (r *builtInRegistry) AddGrant(grant Grant) error {
	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if !strings.HasPrefix(grant.OwnerID, BuiltInPrefix) {
		return fmt.Errorf("built-in grant owner ID must start with %q, got %q", BuiltInPrefix, grant.OwnerID)
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		grant.TeamScope = "*"
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.grants {
		if grantsEquivalent(existing, grant) {
			return nil
		}
	}
	r.grants = append(r.grants, cloneGrant(grant))
	return nil
}

func (r *builtInRegistry) GrantsForOwners(owners []PrincipalRef, req Request) []Grant {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ownerSet := map[string]bool{}
	for _, owner := range owners {
		if owner.Kind == PrincipalRole {
			ownerSet[owner.ID] = true
		}
	}

	now := time.Now().UTC()
	result := make([]Grant, 0, len(r.grants))
	for _, grant := range r.grants {
		if !ownerSet[grant.OwnerID] {
			continue
		}
		if grant.IsExpiredAt(now) {
			continue
		}
		if req.Perm != "" && grant.PermissionName != req.Perm {
			continue
		}
		result = append(result, cloneGrant(grant))
	}
	return result
}

func (r *builtInRegistry) RolesWithPermission(perm string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now().UTC()
	roleMap := map[string]bool{}
	for _, grant := range r.grants {
		if grant.PermissionName == perm && grant.Effect == EffectAllow && !grant.IsExpiredAt(now) {
			roleMap[grant.OwnerID] = true
		}
	}

	result := make([]string, 0, len(roleMap))
	for roleID := range roleMap {
		result = append(result, roleID)
	}
	return result
}
