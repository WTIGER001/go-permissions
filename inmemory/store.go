package inmemory

import (
	"context"
	"fmt"
	"strconv"

	"github.com/wtiger001/go-permissions"
)

type Store struct {
	userGroups           map[string][]string
	userRoleAssignments  map[string][]permissions.RoleAssignment
	groupRoleAssignments map[string][]permissions.RoleAssignment
	roleExpansion        map[string][]string
	grants               []permissions.Grant
}

func NewStore() *Store {
	return &Store{
		userGroups:           map[string][]string{},
		userRoleAssignments:  map[string][]permissions.RoleAssignment{},
		groupRoleAssignments: map[string][]permissions.RoleAssignment{},
		roleExpansion:        map[string][]string{},
		grants:               []permissions.Grant{},
	}
}

func (s *Store) AddUserGroups(userID string, groupIDs ...string) {
	s.userGroups[userID] = append(s.userGroups[userID], groupIDs...)
}

func (s *Store) AddUserRoleAssignments(userID string, assignments ...permissions.RoleAssignment) {
	s.userRoleAssignments[userID] = append(s.userRoleAssignments[userID], assignments...)
}

func (s *Store) AddGroupRoleAssignments(groupID string, assignments ...permissions.RoleAssignment) {
	s.groupRoleAssignments[groupID] = append(s.groupRoleAssignments[groupID], assignments...)
}

func (s *Store) SetRoleExpansion(roleID string, expandedRoleIDs ...string) {
	s.roleExpansion[roleID] = append([]string(nil), expandedRoleIDs...)
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

func (s *Store) ListKnownGroupIDs(_ context.Context) ([]string, error) {
	seen := map[string]bool{}
	groupIDs := make([]string, 0)

	for groupID := range s.groupRoleAssignments {
		if !seen[groupID] {
			seen[groupID] = true
			groupIDs = append(groupIDs, groupID)
		}
	}

	for _, grant := range s.grants {
		if grant.OwnerKind != permissions.PrincipalGroup {
			continue
		}
		if seen[grant.OwnerID] {
			continue
		}
		seen[grant.OwnerID] = true
		groupIDs = append(groupIDs, grant.OwnerID)
	}

	for _, groups := range s.userGroups {
		for _, groupID := range groups {
			if seen[groupID] {
				continue
			}
			seen[groupID] = true
			groupIDs = append(groupIDs, groupID)
		}
	}

	return groupIDs, nil
}

func (s *Store) IsUserInGroup(_ context.Context, userID, groupID string) (bool, error) {
	for _, g := range s.userGroups[userID] {
		if g == groupID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) ListUserGroupIDs(_ context.Context, userID string) ([]string, error) {
	return append([]string(nil), s.userGroups[userID]...), nil
}

func (s *Store) ListRoleAssignmentsForUserAndGroups(_ context.Context, userID string, groupIDs []string) ([]permissions.RoleAssignment, error) {
	result := make([]permissions.RoleAssignment, 0)
	result = append(result, s.userRoleAssignments[userID]...)
	for _, groupID := range groupIDs {
		result = append(result, s.groupRoleAssignments[groupID]...)
	}
	return result, nil
}

func (s *Store) ListExpandedRoleIDs(_ context.Context, roleIDs []string) ([]string, error) {
	seen := map[string]bool{}
	expanded := make([]string, 0, len(roleIDs))

	for _, roleID := range roleIDs {
		if !seen[roleID] {
			seen[roleID] = true
			expanded = append(expanded, roleID)
		}

		children := s.roleExpansion[roleID]
		for _, child := range children {
			if seen[child] {
				continue
			}
			seen[child] = true
			expanded = append(expanded, child)
		}
	}

	return expanded, nil
}

func (s *Store) ListGrantsForOwners(_ context.Context, owners []permissions.PrincipalRef, req permissions.Request) ([]permissions.Grant, error) {
	ownerSet := map[string]bool{}
	for _, owner := range owners {
		ownerSet[string(owner.Kind)+":"+owner.ID] = true
	}

	team := ""
	hasTeam := req.TeamID != nil
	if hasTeam {
		team = strconv.FormatInt(*req.TeamID, 10)
	}

	result := make([]permissions.Grant, 0, len(s.grants))
	for _, grant := range s.grants {
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

func (s *Store) ListPrincipalsWithGrant(_ context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	team := ""
	hasTeam := req.TeamID != nil
	if hasTeam {
		team = strconv.FormatInt(*req.TeamID, 10)
	}

	allowByPrincipal := map[string]permissions.PrincipalHit{}
	deniedPrincipal := map[string]bool{}

	for _, grant := range s.grants {
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
