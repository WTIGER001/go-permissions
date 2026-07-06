package inmemory

import (
	"context"
	"fmt"
	"time"

	"github.com/wtiger001/go-permissions"
)

type Store struct {
	userRoleAssignments  map[string][]permissions.RoleAssignment
	groupRoleAssignments map[string][]permissions.RoleAssignment
	// roleExpansion holds the explicitly set expansion for testing convenience
	// (legacy helper kept for direct test seeding; AddRoleInheritance is preferred).
	roleExpansion        map[string][]string
	// roleInheritance maps parent -> set of direct child role IDs.
	roleInheritance      map[string]map[string]bool
	// roleClosure maps ancestor -> set of all descendant role IDs (transitive).
	roleClosure         map[string]map[string]bool
	grants               []permissions.Grant
}

var _ permissions.PermissionStore = (*Store)(nil)

func NewStore() *Store {
	return &Store{
		userRoleAssignments:  map[string][]permissions.RoleAssignment{},
		groupRoleAssignments: map[string][]permissions.RoleAssignment{},
		roleExpansion:        map[string][]string{},
		roleInheritance:      map[string]map[string]bool{},
		roleClosure:         map[string]map[string]bool{},
		grants:               []permissions.Grant{},
	}
}

func (s *Store) AddUserRoleAssignments(userID string, assignments ...permissions.RoleAssignment) {
	s.userRoleAssignments[userID] = append(s.userRoleAssignments[userID], assignments...)
}

func (s *Store) AddGroupRoleAssignments(groupID string, assignments ...permissions.RoleAssignment) {
	s.groupRoleAssignments[groupID] = append(s.groupRoleAssignments[groupID], assignments...)
}

// SetRoleExpansion is a legacy helper for direct test seeding of the expansion
// map. Prefer AddRoleInheritance for transitive closure support.
func (s *Store) SetRoleExpansion(roleID string, expandedRoleIDs ...string) {
	s.roleExpansion[roleID] = append([]string(nil), expandedRoleIDs...)
	// Mirror into closure so ExpandRoles stays consistent.
	for _, child := range expandedRoleIDs {
		_ = s.AddRoleInheritance(context.Background(), roleID, child) //nolint: errcheck - best-effort mirroring
	}
}

// AddRoleInheritance declares that parentRoleID inherits all permissions of
// childRoleID and recomputes the full transitive role closure.
func (s *Store) AddRoleInheritance(_ context.Context, parentRoleID, childRoleID string) error {
	if parentRoleID == "" {
		return fmt.Errorf("parent role ID is required")
	}
	if childRoleID == "" {
		return fmt.Errorf("child role ID is required")
	}
	if parentRoleID == childRoleID {
		return fmt.Errorf("a role cannot inherit itself")
	}

	if s.roleInheritance[parentRoleID] == nil {
		s.roleInheritance[parentRoleID] = map[string]bool{}
	}
	if s.roleInheritance[parentRoleID][childRoleID] {
		return nil
	}
	s.roleInheritance[parentRoleID][childRoleID] = true

	// Self-closure entries.
	if s.roleClosure[parentRoleID] == nil {
		s.roleClosure[parentRoleID] = map[string]bool{parentRoleID: true}
	}
	if s.roleClosure[childRoleID] == nil {
		s.roleClosure[childRoleID] = map[string]bool{childRoleID: true}
	}

	newDescendants := s.roleClosure[childRoleID]
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

func (s *Store) AddGrants(grants ...permissions.Grant) {
	s.grants = append(s.grants, grants...)
}

func (s *Store) CreateGrant(_ context.Context, grant permissions.Grant) error {
	s.AddGrants(grant)
	return nil
}

func (s *Store) AssignRole(_ context.Context, principal permissions.PrincipalRef, roleID string, bindingValues map[string]any) error {
	if err := principal.Validate(); err != nil {
		return err
	}

	assignment := permissions.RoleAssignment{RoleID: roleID, BindingValues: map[string]any{}}
	for k, v := range bindingValues {
		assignment.BindingValues[k] = v
	}

	switch principal.Kind {
	case permissions.PrincipalUser:
		s.AddUserRoleAssignments(principal.ID, assignment)
	case permissions.PrincipalGroup:
		s.AddGroupRoleAssignments(principal.ID, assignment)
	default:
		return fmt.Errorf("role assignments support only user or group principals")
	}

	return nil
}

func (s *Store) RoleAssignmentsForPrincipal(_ context.Context, principal permissions.PrincipalRef) ([]permissions.RoleAssignment, error) {
	switch principal.Kind {
	case permissions.PrincipalUser:
		return append([]permissions.RoleAssignment(nil), s.userRoleAssignments[principal.ID]...), nil
	case permissions.PrincipalGroup:
		return append([]permissions.RoleAssignment(nil), s.groupRoleAssignments[principal.ID]...), nil
	default:
		return nil, nil
	}
}

func (s *Store) ExpandRoles(_ context.Context, roleIDs []string) ([]string, error) {
	seen := map[string]bool{}
	expanded := make([]string, 0, len(roleIDs))

	for _, roleID := range roleIDs {
		if !seen[roleID] {
			seen[roleID] = true
			expanded = append(expanded, roleID)
		}
		// Use the roleClosure table for fully transitive expansion.
		for descendant := range s.roleClosure[roleID] {
			if !seen[descendant] {
				seen[descendant] = true
				expanded = append(expanded, descendant)
			}
		}
		// Fallback: also honour legacy SetRoleExpansion entries.
		for _, child := range s.roleExpansion[roleID] {
			if !seen[child] {
				seen[child] = true
				expanded = append(expanded, child)
			}
		}
	}

	return expanded, nil
}

func (s *Store) GrantsForOwners(_ context.Context, owners []permissions.PrincipalRef, req permissions.Request) ([]permissions.Grant, error) {
	now := time.Now().UTC()
	ownerSet := map[string]bool{}
	for _, owner := range owners {
		ownerSet[string(owner.Kind)+":"+owner.ID] = true
	}

	team := req.TeamID
	hasTeam := req.TeamID != ""

	result := make([]permissions.Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		if !grant.IsActiveAt(now) {
			continue
		}
		if !ownerSet[string(grant.OwnerKind)+":"+grant.OwnerID] {
			continue
		}
		if req.Perm != "" && grant.PermissionName != req.Perm {
			continue
		}

		if hasTeam {
			if grant.TeamScope != "*" && grant.TeamScope != team {
				continue
			}
		} else {
			if grant.TeamScope != "*" {
				continue
			}
		}

		if grant.ObjectScope != nil && *grant.ObjectScope != "*" && *grant.ObjectScope != req.Object {
			continue
		}

		result = append(result, grant)
	}

	return result, nil
}

func (s *Store) GrantsForPrincipal(ctx context.Context, principal permissions.PrincipalRef) ([]permissions.Grant, error) {
	return s.GrantsForOwners(ctx, []permissions.PrincipalRef{principal}, permissions.Request{})
}

func (s *Store) PrincipalsWithGrant(_ context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	now := time.Now().UTC()
	team := req.TeamID
	hasTeam := req.TeamID != ""

	allowByPrincipal := map[string]permissions.PrincipalHit{}
	deniedPrincipal := map[string]bool{}

	for _, grant := range s.grants {
		if !grant.IsActiveAt(now) {
			continue
		}
		if req.Perm != "" && grant.PermissionName != req.Perm {
			continue
		}

		if hasTeam {
			if grant.TeamScope != "*" && grant.TeamScope != team {
				continue
			}
		} else if grant.TeamScope != "*" {
			continue
		}

		if grant.ObjectScope != nil && *grant.ObjectScope != "*" && *grant.ObjectScope != req.Object {
			continue
		}

		principalKey := string(grant.OwnerKind) + ":" + grant.OwnerID
		if grant.Effect == permissions.EffectDeny {
			deniedPrincipal[principalKey] = true
			delete(allowByPrincipal, principalKey)
			continue
		}

		if deniedPrincipal[principalKey] {
			continue
		}

		if _, exists := allowByPrincipal[principalKey]; exists {
			continue
		}

		allowByPrincipal[principalKey] = permissions.PrincipalHit{
			Kind:           grant.OwnerKind,
			ID:             grant.OwnerID,
			TeamScope:      grant.TeamScope,
			ObjectScope:    grant.ObjectScope,
			PermissionName: grant.PermissionName,
		}
	}

	result := make([]permissions.PrincipalHit, 0, len(allowByPrincipal))
	for _, hit := range allowByPrincipal {
		result = append(result, hit)
	}

	return result, nil
}

func (s *Store) RoleDefinitions(_ context.Context) ([]permissions.Role, error) {
	return []permissions.Role{}, nil
}

func (s *Store) RoleDefinition(_ context.Context, roleID string) (permissions.Role, error) {
	if roleID == "" {
		return permissions.Role{}, fmt.Errorf("role ID is required")
	}

	return permissions.Role{ID: roleID, Name: roleID, VariableSpec: map[string]any{}, Permissions: []string{}, BuiltIn: false, IsDisabled: false}, nil
}

func (s *Store) CreateRole(_ context.Context, _ permissions.Role) error { return nil }
func (s *Store) UpdateRole(_ context.Context, _ permissions.Role) error { return nil }
func (s *Store) DeleteRole(_ context.Context, _ string) error           { return nil }

func (s *Store) DeleteGrantsForOwner(_ context.Context, ownerKind permissions.PrincipalKind, ownerID string) error {
	filtered := make([]permissions.Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		if grant.OwnerKind == ownerKind && grant.OwnerID == ownerID {
			continue
		}
		filtered = append(filtered, grant)
	}
	s.grants = filtered
	return nil
}

func (s *Store) DisableBuiltInRole(_ context.Context, _ string) error { return nil }
func (s *Store) EnableBuiltInRole(_ context.Context, _ string) error  { return nil }
func (s *Store) DisabledBuiltInRoles(_ context.Context) ([]string, error) {
	return []string{}, nil
}

