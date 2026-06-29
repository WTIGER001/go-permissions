package jsonstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/wtiger001/go-permissions"
)

type Data struct {
	UserGroups           map[string][]string                     `json:"user_groups"`
	UserRoleAssignments  map[string][]permissions.RoleAssignment `json:"user_role_assignments"`
	GroupRoleAssignments map[string][]permissions.RoleAssignment `json:"group_role_assignments"`
	// RoleInheritance stores the direct parent->children edges for persistence.
	RoleInheritance      map[string][]string                     `json:"role_inheritance"`
	// RoleExpansion is kept for backward-compatible test seeding only.
	RoleExpansion        map[string][]string                     `json:"role_expansion"`
	Grants               []permissions.Grant                     `json:"grants"`
}

type Store struct {
	path string
	mu   sync.RWMutex
	data Data
}

var _ permissions.PermissionStore = (*Store)(nil)

func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}

	s := &Store{path: path, data: emptyData()}
	if err := s.Load(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	content, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.data = emptyData()
			return nil
		}
		return fmt.Errorf("read store file: %w", err)
	}

	if len(content) == 0 {
		s.data = emptyData()
		return nil
	}

	var parsed Data
	if err := json.Unmarshal(content, &parsed); err != nil {
		return fmt.Errorf("decode store file: %w", err)
	}

	s.data = normalizeData(parsed)
	return nil
}

func (s *Store) Save() error {
	s.mu.RLock()
	data := cloneData(s.data)
	s.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}

	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode store data: %w", err)
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o644); err != nil {
		return fmt.Errorf("write temp store file: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace store file: %w", err)
	}

	return nil
}

func (s *Store) Snapshot() Data {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return cloneData(s.data)
}

func (s *Store) SetData(data Data) error {
	s.mu.Lock()
	s.data = normalizeData(data)
	s.mu.Unlock()

	return s.Save()
}

func (s *Store) CreateGrant(_ context.Context, grant permissions.Grant) error {
	s.mu.Lock()
	s.data.Grants = append(s.data.Grants, cloneGrant(grant))
	s.mu.Unlock()

	return s.Save()
}

func (s *Store) AssignRole(_ context.Context, principal permissions.PrincipalRef, roleID string, bindingValues map[string]any) error {
	if err := principal.Validate(); err != nil {
		return err
	}

	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	assignment := permissions.RoleAssignment{RoleID: roleID, BindingValues: map[string]any{}}
	for k, v := range bindingValues {
		assignment.BindingValues[k] = v
	}

	s.mu.Lock()
	switch principal.Kind {
	case permissions.PrincipalUser:
		s.data.UserRoleAssignments[principal.ID] = append(s.data.UserRoleAssignments[principal.ID], assignment)
	case permissions.PrincipalGroup:
		s.data.GroupRoleAssignments[principal.ID] = append(s.data.GroupRoleAssignments[principal.ID], assignment)
	default:
		s.mu.Unlock()
		return fmt.Errorf("role assignments support only user or group principals")
	}
	s.mu.Unlock()

	return s.Save()
}

func (s *Store) ListKnownGroupIDs(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := map[string]bool{}
	groupIDs := make([]string, 0)

	for groupID := range s.data.GroupRoleAssignments {
		if !seen[groupID] {
			seen[groupID] = true
			groupIDs = append(groupIDs, groupID)
		}
	}

	for _, grant := range s.data.Grants {
		if grant.OwnerKind != permissions.PrincipalGroup {
			continue
		}
		if seen[grant.OwnerID] {
			continue
		}
		seen[grant.OwnerID] = true
		groupIDs = append(groupIDs, grant.OwnerID)
	}

	for _, groups := range s.data.UserGroups {
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
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, g := range s.data.UserGroups[userID] {
		if g == groupID {
			return true, nil
		}
	}

	return false, nil
}

func (s *Store) GetUserGroups(_ context.Context, userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return append([]string(nil), s.data.UserGroups[userID]...), nil
}

func (s *Store) GetGroupMembers(_ context.Context, groupID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	members := make([]string, 0)
	for userID, groups := range s.data.UserGroups {
		for _, g := range groups {
			if g == groupID {
				members = append(members, userID)
				break
			}
		}
	}

	return members, nil
}

func (s *Store) ListRoleAssignmentsForUserAndGroups(_ context.Context, userID string, groupIDs []string) ([]permissions.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]permissions.RoleAssignment, 0)
	result = append(result, cloneRoleAssignments(s.data.UserRoleAssignments[userID])...)
	for _, groupID := range groupIDs {
		result = append(result, cloneRoleAssignments(s.data.GroupRoleAssignments[groupID])...)
	}

	return result, nil
}

func (s *Store) RoleAssignmentsForPrincipal(_ context.Context, principal permissions.PrincipalRef) ([]permissions.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch principal.Kind {
	case permissions.PrincipalUser:
		return cloneRoleAssignments(s.data.UserRoleAssignments[principal.ID]), nil
	case permissions.PrincipalGroup:
		return cloneRoleAssignments(s.data.GroupRoleAssignments[principal.ID]), nil
	default:
		return nil, nil
	}
}

func (s *Store) ListExpandedRoleIDs(_ context.Context, roleIDs []string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return transitiveExpand(roleIDs, s.data.RoleInheritance, s.data.RoleExpansion), nil
}

// transitiveExpand walks the RoleInheritance and (legacy) RoleExpansion maps
// recursively and returns every transitively reachable descendant of the given
// seed roleIDs, including the seeds themselves.
func transitiveExpand(roleIDs []string, inheritance, legacy map[string][]string) []string {
	seen := map[string]bool{}
	queue := append([]string(nil), roleIDs...)
	expanded := make([]string, 0, len(roleIDs))

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current] {
			continue
		}
		seen[current] = true
		expanded = append(expanded, current)

		for _, child := range inheritance[current] {
			if !seen[child] {
				queue = append(queue, child)
			}
		}
		for _, child := range legacy[current] {
			if !seen[child] {
				queue = append(queue, child)
			}
		}
	}
	return expanded
}

// AddRoleInheritance persists a parent→child direct edge and saves the store.
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

	s.mu.Lock()
	for _, existing := range s.data.RoleInheritance[parentRoleID] {
		if existing == childRoleID {
			s.mu.Unlock()
			return nil
		}
	}
	s.data.RoleInheritance[parentRoleID] = append(s.data.RoleInheritance[parentRoleID], childRoleID)
	s.mu.Unlock()

	return s.Save()
}

func (s *Store) ExpandRoles(ctx context.Context, roleIDs []string) ([]string, error) {
	return s.ListExpandedRoleIDs(ctx, roleIDs)
}

func (s *Store) ListGrantsForOwners(_ context.Context, owners []permissions.PrincipalRef, req permissions.Request) ([]permissions.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()

	ownerSet := map[string]bool{}
	for _, owner := range owners {
		ownerSet[string(owner.Kind)+":"+owner.ID] = true
	}

	hasTeam := req.TeamID != nil
	team := ""
	if hasTeam {
		team = strconv.FormatInt(*req.TeamID, 10)
	}

	result := make([]permissions.Grant, 0, len(s.data.Grants))
	for _, grant := range s.data.Grants {
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
		} else if grant.TeamScope != "*" {
			continue
		}

		if grant.ObjectScope != nil && *grant.ObjectScope != "*" && *grant.ObjectScope != req.Object {
			continue
		}

		result = append(result, cloneGrant(grant))
	}

	return result, nil
}

func (s *Store) GrantsForOwners(ctx context.Context, owners []permissions.PrincipalRef, req permissions.Request) ([]permissions.Grant, error) {
	return s.ListGrantsForOwners(ctx, owners, req)
}

func (s *Store) GrantsForPrincipal(ctx context.Context, principal permissions.PrincipalRef) ([]permissions.Grant, error) {
	return s.ListGrantsForOwners(ctx, []permissions.PrincipalRef{principal}, permissions.Request{})
}

func (s *Store) ListPrincipalsWithGrant(_ context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()

	hasTeam := req.TeamID != nil
	team := ""
	if hasTeam {
		team = strconv.FormatInt(*req.TeamID, 10)
	}

	allowByPrincipal := map[string]permissions.PrincipalHit{}
	deniedPrincipal := map[string]bool{}

	for _, grant := range s.data.Grants {
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
			ObjectScope:    cloneStringPtr(grant.ObjectScope),
			PermissionName: grant.PermissionName,
		}
	}

	result := make([]permissions.PrincipalHit, 0, len(allowByPrincipal))
	for _, hit := range allowByPrincipal {
		result = append(result, hit)
	}

	return result, nil
}

func (s *Store) PrincipalsWithGrant(ctx context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	return s.ListPrincipalsWithGrant(ctx, req)
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
	s.mu.Lock()
	filtered := make([]permissions.Grant, 0, len(s.data.Grants))
	for _, grant := range s.data.Grants {
		if grant.OwnerKind == ownerKind && grant.OwnerID == ownerID {
			continue
		}
		filtered = append(filtered, grant)
	}
	s.data.Grants = filtered
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) DisableBuiltInRole(_ context.Context, _ string) error { return nil }
func (s *Store) EnableBuiltInRole(_ context.Context, _ string) error  { return nil }
func (s *Store) DisabledBuiltInRoles(_ context.Context) ([]string, error) {
	return []string{}, nil
}


func emptyData() Data {
	return Data{
		UserGroups:           map[string][]string{},
		UserRoleAssignments:  map[string][]permissions.RoleAssignment{},
		GroupRoleAssignments: map[string][]permissions.RoleAssignment{},
		RoleInheritance:      map[string][]string{},
		RoleExpansion:        map[string][]string{},
		Grants:               []permissions.Grant{},
	}
}

func normalizeData(data Data) Data {
	if data.UserGroups == nil {
		data.UserGroups = map[string][]string{}
	}
	if data.UserRoleAssignments == nil {
		data.UserRoleAssignments = map[string][]permissions.RoleAssignment{}
	}
	if data.GroupRoleAssignments == nil {
		data.GroupRoleAssignments = map[string][]permissions.RoleAssignment{}
	}
	if data.RoleInheritance == nil {
		data.RoleInheritance = map[string][]string{}
	}
	if data.RoleExpansion == nil {
		data.RoleExpansion = map[string][]string{}
	}
	if data.Grants == nil {
		data.Grants = []permissions.Grant{}
	}
	return data
}

func cloneData(data Data) Data {
	cloned := emptyData()

	for userID, groups := range data.UserGroups {
		cloned.UserGroups[userID] = append([]string(nil), groups...)
	}

	for userID, assignments := range data.UserRoleAssignments {
		cloned.UserRoleAssignments[userID] = cloneRoleAssignments(assignments)
	}

	for groupID, assignments := range data.GroupRoleAssignments {
		cloned.GroupRoleAssignments[groupID] = cloneRoleAssignments(assignments)
	}

	for roleID, children := range data.RoleInheritance {
		cloned.RoleInheritance[roleID] = append([]string(nil), children...)
	}

	for roleID, children := range data.RoleExpansion {
		cloned.RoleExpansion[roleID] = append([]string(nil), children...)
	}

	cloned.Grants = make([]permissions.Grant, 0, len(data.Grants))
	for _, grant := range data.Grants {
		cloned.Grants = append(cloned.Grants, cloneGrant(grant))
	}

	return cloned
}

func cloneRoleAssignments(assignments []permissions.RoleAssignment) []permissions.RoleAssignment {
	if len(assignments) == 0 {
		return nil
	}

	result := make([]permissions.RoleAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		copied := permissions.RoleAssignment{
			RoleID:        assignment.RoleID,
			BindingValues: map[string]any{},
		}
		for k, v := range assignment.BindingValues {
			copied.BindingValues[k] = v
		}
		result = append(result, copied)
	}

	return result
}

func cloneGrant(grant permissions.Grant) permissions.Grant {
	copyGrant := grant
	copyGrant.ObjectScope = cloneStringPtr(grant.ObjectScope)
	copyGrant.ExpiresAt = cloneTimePtr(grant.ExpiresAt)
	copyGrant.RestrictedFields = append([]string(nil), grant.RestrictedFields...)
	copyGrant.VariableSpec = map[string]any{}
	for k, v := range grant.VariableSpec {
		copyGrant.VariableSpec[k] = v
	}
	return copyGrant
}

func cloneStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	copyV := *v
	return &copyV
}

func cloneTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	copyV := *v
	return &copyV
}
