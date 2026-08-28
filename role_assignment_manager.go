package permissions

import (
	"context"
	"fmt"
	"slices"

	"github.com/hashicorp/go-multierror"
)

type roleAssignmentManagerBase struct {
	service      *Service
	managedRoles []string
	objectScope  *string
	teamScope    *string
}

type RoleAssignmentManager struct {
	roleAssignmentManagerBase
	assignmentRules []RoleAssignmentRule
	removeRules     []PrincipalRemovalRule
}

type PrincipalRemovalRule interface {
	ValidateRemoval(removingUsers, removingGroups []string, manager *roleAssignmentManagerBase) error
}

type RoleAssignmentRule interface {
	ValidateAssignment(current []RoleAssignment, proposed []RoleAssignment, assignee PrincipalRef, assigner *PrincipalRef, manager *roleAssignmentManagerBase) error
}

func (m *RoleAssignmentManager) AddRemovalRule(rule PrincipalRemovalRule) {
	m.removeRules = append(m.removeRules, rule)
}

func (m *RoleAssignmentManager) AddAssignmentRule(rule RoleAssignmentRule) {
	m.assignmentRules = append(m.assignmentRules, rule)
}

// Instantiates a new Role Assignment manager. This is meant to be used and disposed of quickly.
// The "ram" is simply a collection of helpers and rules to perform validation when assigning/unassigning roles.
func NewRoleAssignmentManager(service *Service, roles []string, obj *string, team *string) *RoleAssignmentManager {
	return &RoleAssignmentManager{
		roleAssignmentManagerBase: roleAssignmentManagerBase{
			service:      service,
			managedRoles: roles,
			objectScope:  obj,
			teamScope:    team,
		},
		assignmentRules: []RoleAssignmentRule{},
		removeRules:     []PrincipalRemovalRule{},
	}
}

// Validate a transition from current → proposed
func (m *RoleAssignmentManager) canMakeAssignmentChange(ctx context.Context, assignee PrincipalRef, assigner *PrincipalRef, desired []string) error {
	currentAssignments, err := m.service.RoleAssignmentsForPrincipal(ctx, assignee)
	if err != nil {
		return err
	}

	filtered := filterAssignmentsByScope(currentAssignments, m.teamScope, m.objectScope)

	add, remove, err := m.computeProposed(ctx, assignee, desired)
	if err != nil {
		return err
	}

	proposed := []RoleAssignment{}
	// Build proposed list: current minus removed plus added
	for _, c := range filtered {
		if !contains(remove, c.RoleID) {
			proposed = append(proposed, c)
		}
	}
	for _, a := range add {
		proposed = append(proposed, RoleAssignment{RoleID: a})
	}

	for _, rule := range m.assignmentRules {
		if err := rule.ValidateAssignment(filtered, proposed, assignee, assigner, &m.roleAssignmentManagerBase); err != nil {
			return err
		}
	}

	return nil
}

func (m *RoleAssignmentManager) CanAddRoles(ctx context.Context, assignee PrincipalRef, assigner *PrincipalRef, add []string) error {
	current, err := m.service.RoleAssignmentsForPrincipal(ctx, assignee)
	if err != nil {
		return err
	}

	filtered := filterAssignmentsByScope(current, m.teamScope, m.objectScope)

	desired := []string{}
	for _, c := range filtered {
		desired = append(desired, c.RoleID)
	}
	desired = append(desired, add...)

	return m.canMakeAssignmentChange(ctx, assignee, assigner, desired)
}

func (m *RoleAssignmentManager) AddRoles(ctx context.Context, assignee PrincipalRef, roles []string, assigner *PrincipalRef) error {

	// First verify the change is allowed
	if err := m.CanAddRoles(ctx, assignee, assigner, roles); err != nil {
		return err
	}

	// Apply additions
	for _, roleID := range roles {
		if err := m.assignRole(ctx, assignee, roleID); err != nil {
			return err
		}
	}

	return nil
}

func (m *RoleAssignmentManager) CanRemoveRoles(ctx context.Context, assignee PrincipalRef, assigner *PrincipalRef, remove []string) error {
	current, err := m.service.RoleAssignmentsForPrincipal(ctx, assignee)
	if err != nil {
		return err
	}

	filtered := filterAssignmentsByScope(current, m.teamScope, m.objectScope)

	desired := []string{}
	for _, c := range filtered {
		if !contains(remove, c.RoleID) {
			desired = append(desired, c.RoleID)
		}
	}

	return m.canMakeAssignmentChange(ctx, assignee, assigner, desired)
}

func (m *RoleAssignmentManager) RemoveRoles(ctx context.Context, assignee PrincipalRef, roles []string, assigner *PrincipalRef) error {

	// First verify the change is allowed
	if err := m.CanRemoveRoles(ctx, assignee, assigner, roles); err != nil {
		return err
	}

	// Apply removals
	for _, roleID := range roles {
		if err := m.unassignRole(ctx, assignee, roleID); err != nil {
			return err
		}
	}

	return nil
}

// AssignRole assigns the given role with appropriate binding values.
func (m *RoleAssignmentManager) assignRole(ctx context.Context, principal PrincipalRef, roleID string) error {
	bindings := map[string]any{}
	if m.teamScope != nil {
		bindings["team"] = *m.teamScope
	}
	if m.objectScope != nil {
		bindings["object"] = *m.objectScope
	}
	return m.service.AssignRole(ctx, principal, roleID, bindings)
}

// UnassignRole unassigns the given role with appropriate binding values.
func (m *RoleAssignmentManager) unassignRole(ctx context.Context, principal PrincipalRef, roleID string) error {
	bindings := map[string]any{}
	if m.teamScope != nil {
		bindings["team"] = *m.teamScope
	}
	if m.objectScope != nil {
		bindings["object"] = *m.objectScope
	}
	return m.service.UnassignRole(ctx, principal, roleID, bindings)
}

// computeProposed determines which assignments should be added and removed.
// computeProposed now fetches current assignments automatically.
func (m *RoleAssignmentManager) computeProposed(ctx context.Context, principal PrincipalRef, desired []string) (add []string, remove []string, err error) {
	currentAssignments, err := m.service.RoleAssignmentsForPrincipal(ctx, principal)
	if err != nil {
		return nil, nil, err
	}

	filtered := filterAssignmentsByScope(currentAssignments, m.teamScope, m.objectScope)

	currentSet := map[string]bool{}
	for _, c := range filtered {
		currentSet[c.RoleID] = true
	}

	desiredSet := map[string]bool{}
	for _, d := range desired {
		desiredSet[d] = true
	}

	for d := range desiredSet {
		if !currentSet[d] {
			add = append(add, d)
		}
	}

	for c := range currentSet {
		if !desiredSet[c] {
			remove = append(remove, c)
		}
	}

	return add, remove, nil
}

func (m *RoleAssignmentManager) RemoveBulkUsers(ctx context.Context, users, groups []string, assigner *PrincipalRef) error {
	err := m.CanRemoveBulkUsers(ctx, users, groups)
	if err != nil {
		return err
	}

	var merr *multierror.Error

	for _, user := range users {
		current, err := m.service.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: user})
		if err != nil {
			return err
		}

		filtered := filterAssignmentsByScope(current, m.teamScope, m.objectScope)

		roles := []string{}
		for _, ra := range filtered {
			roles = append(roles, ra.RoleID)
		}

		err = m.RemoveRoles(ctx, PrincipalRef{Kind: PrincipalUser, ID: user}, roles, assigner)
		if err != nil {
			merr = multierror.Append(merr, merr, err)
		}
	}

	for _, group := range groups {
		current, err := m.service.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalGroup, ID: group})
		if err != nil {
			return err
		}

		filtered := filterAssignmentsByScope(current, m.teamScope, m.objectScope)

		roles := []string{}
		for _, ra := range filtered {
			roles = append(roles, ra.RoleID)
		}

		err = m.RemoveRoles(ctx, PrincipalRef{Kind: PrincipalGroup, ID: group}, roles, assigner)
		if err != nil {
			merr = multierror.Append(merr, merr, err)
		}
	}

	return merr.ErrorOrNil()
}

func (m *RoleAssignmentManager) CanRemoveBulkUsers(ctx context.Context, users, groups []string) error {
	for _, rule := range m.removeRules {
		if err := rule.ValidateRemoval(users, groups, &m.roleAssignmentManagerBase); err != nil {
			return err
		}
	}

	return nil
}

// CleanupAllRoleAssignments removes all role assignments scoped to all roles managed by the role manager
// Only use this when you are "deleting" an object or team and want to remove all instances of roles
// assigned to the resource
func (m *RoleAssignmentManager) CleanupAllRoleAssignments(ctx context.Context) error {
	var merr *multierror.Error

	// Fetch all assignments for the managed roles
	for _, roleID := range m.managedRoles {
		assignments, err := m.service.RoleAssignmentsForRoleID(ctx, roleID)
		if err != nil {
			merr = multierror.Append(merr, err)
			continue
		}

		// Filter assignments by scope
		filtered := filterAssignmentHitsByScope(assignments, m.teamScope, m.objectScope)

		for _, hit := range filtered {
			principal := hit.PrincipalRef

			if err := m.unassignRole(ctx, principal, roleID); err != nil {
				merr = multierror.Append(merr, err)
			}
		}
	}

	return merr.ErrorOrNil()
}

func contains(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// **BUILT-IN RULES**

// CannotAddSelfRule prevents a principal from assigning roles to themselves.
// If RoleIDs is nil or empty, ALL roles are prohibited.
// If RoleIDs has entries, ONLY those roles are prohibited.
type CannotAddSelfRule struct {
	RoleIDs []string // optional: which roles cannot be self-assigned
}

func (r CannotAddSelfRule) ValidateAssignment(
	current []RoleAssignment,
	proposed []RoleAssignment,
	assignee PrincipalRef,
	assigner *PrincipalRef,
	ram *roleAssignmentManagerBase,
) error {

	// If assigner is nil → always allow
	if assigner == nil {
		return nil
	}

	// Build a quick lookup of roles the principal already has in-scope
	currentSet := map[string]bool{}
	for _, c := range current {
		currentSet[c.RoleID] = true
	}

	// Check each role in proposed
	for _, p := range proposed {
		// Only consider newly added roles
		if currentSet[p.RoleID] {
			continue
		}

		// Only block additions to self
		if assigner.ID != assignee.ID ||
			assigner.Kind != assignee.Kind {
			continue
		}

		// If RoleIDs is empty → ANY role is prohibited
		if len(r.RoleIDs) == 0 {
			return fmt.Errorf("principal %s cannot add roles to themselves", assignee.ID)
		}

		// Otherwise only prohibit specific roleIDs
		if slices.Contains(r.RoleIDs, p.RoleID) {
			return fmt.Errorf(
				"principal %s cannot self-assign role %s",
				assignee.ID, p.RoleID,
			)
		}
	}

	return nil
}

// CannotRemoveSelfRule prevents a principal from removing roles from themselves.
// If RoleIDs is nil or empty, ANY role removal is prohibited.
// If RoleIDs has entries, ONLY those roles cannot be self-removed.
type CannotRemoveSelfRule struct {
	RoleIDs []string // optional: which roles cannot be self-removed
}

func (r CannotRemoveSelfRule) ValidateAssignment(
	current []RoleAssignment,
	proposed []RoleAssignment,
	assignee PrincipalRef,
	assigner *PrincipalRef,
	ram *roleAssignmentManagerBase,
) error {
	// If assigner is nil → always allow
	if assigner == nil {
		return nil
	}

	// Only process removals when assigner == assignee
	if assigner.ID != assignee.ID || assigner.Kind != assignee.Kind {
		return nil
	}

	// Build lookup for proposed roles
	proposedSet := map[string]bool{}
	for _, p := range proposed {
		proposedSet[p.RoleID] = true
	}

	// Build removal list by finding roles missing from proposed
	for _, c := range current {
		if proposedSet[c.RoleID] {
			continue
		}

		// This role is being removed by the principal from themselves

		// If RoleIDs is empty → ANY role removal is prohibited
		if len(r.RoleIDs) == 0 {
			return fmt.Errorf("principal %s cannot remove roles from themselves", assignee.ID)
		}

		// Otherwise only prohibit specific RoleIDs
		if slices.Contains(r.RoleIDs, c.RoleID) {
			return fmt.Errorf(
				"principal %s cannot self-remove role %s",
				assignee.ID, c.RoleID,
			)
		}
	}

	return nil
}

// Prohibit combining two specific roles simultaneously
// Useful for situations where roles conflict, e.g. team.owner and team.guest
// cannot be held at the same time.
type CannotCombineRolesRule struct {
	RoleA string
	RoleB string
}

func (r CannotCombineRolesRule) ValidateAssignment(_ []RoleAssignment, proposed []RoleAssignment, assignee PrincipalRef, assigner *PrincipalRef, ram *roleAssignmentManagerBase) error {
	hasA := false
	hasB := false
	for _, a := range proposed {
		if a.RoleID == r.RoleA {
			hasA = true
		}
		if a.RoleID == r.RoleB {
			hasB = true
		}
	}
	if hasA && hasB {
		return fmt.Errorf("cannot combine roles %s and %s", r.RoleA, r.RoleB)
	}
	return nil
}

// Set bounds on the number of instances of a role
// Useful for roles that are expected to be assigned only a certain number of times
type MinMaxInstancesRule struct {
	RoleID string
	Min    int
	Max    int
	Kind   *PrincipalKind
}

func (r MinMaxInstancesRule) ValidateAssignment(
	current []RoleAssignment,
	proposed []RoleAssignment,
	assignee PrincipalRef,
	assigner *PrincipalRef,
	ram *roleAssignmentManagerBase,
) error {

	// Fetch all assignments for this RoleID (regardless of principal)
	assignments, err := ram.service.RoleAssignmentsForRoleID(context.Background(), r.RoleID)
	if err != nil {
		return err
	}

	// Scope filter (team + object)
	filtered := filterAssignmentHitsByScope(assignments, ram.teamScope, ram.objectScope)

	// Build maps for role presence in current & proposed
	currentSet := map[string]bool{}
	for _, c := range current {
		if c.RoleID == r.RoleID {
			currentSet[assignee.ID] = true
		}
	}

	proposedSet := map[string]bool{}
	for _, p := range proposed {
		if p.RoleID == r.RoleID {
			proposedSet[assignee.ID] = true
		}
	}

	// Count final totals after applying the proposed mutation
	userCount := 0
	groupCount := 0

	for _, assignment := range filtered {
		id := assignment.PrincipalRef.ID

		// This principal has the role *in final proposed state* if:
		//   it was assigned originally and not removed, OR
		//   it is newly added.
		// So: proposedSet contains final state.
		hasRole := proposedSet[id]

		if hasRole {
			switch assignment.PrincipalRef.Kind {
			case PrincipalUser:
				userCount++
			case PrincipalGroup:
				groupCount++
			}
		}
	}

	// Apply Kind filter (if specified)
	if r.Kind != nil {
		switch *r.Kind {
		case PrincipalUser:
			if userCount < r.Min {
				return fmt.Errorf(
					"role %s requires at least %d users, but only %d would remain",
					r.RoleID, r.Min, userCount,
				)
			}
			if r.Max > 0 && userCount > r.Max {
				return fmt.Errorf(
					"role %s allows at most %d users, but %d would exist",
					r.RoleID, r.Max, userCount,
				)
			}
		case PrincipalGroup:
			if groupCount < r.Min {
				return fmt.Errorf(
					"role %s requires at least %d groups, but only %d would remain",
					r.RoleID, r.Min, groupCount,
				)
			}
			if r.Max > 0 && groupCount > r.Max {
				return fmt.Errorf(
					"role %s allows at most %d groups, but %d would exist",
					r.RoleID, r.Max, groupCount,
				)
			}
		}
		return nil
	}

	// No Kind restriction → enforce totals across users + groups
	total := userCount + groupCount

	if total < r.Min {
		return fmt.Errorf(
			"role %s requires at least %d principals, but only %d would remain",
			r.RoleID, r.Min, total,
		)
	}

	if r.Max > 0 && total > r.Max {
		return fmt.Errorf(
			"role %s allows at most %d principals, but %d would exist",
			r.RoleID, r.Max, total,
		)
	}

	return nil
}

// Before removing users, check if at least {min} number of assignments exist for role
// and optionally a role assigned to a kind of principal
type RequireAtLeastRule struct {
	RoleID string
	Min    int
	Kind   *PrincipalKind
}

func (r RequireAtLeastRule) ValidateRemoval(users []string, groups []string, ram *roleAssignmentManagerBase) error {
	// Get current assignments for the provided roleID
	assignments, err := ram.service.RoleAssignmentsForRoleID(context.Background(), r.RoleID)
	if err != nil {
		return err
	}

	currUsersInAssignment := 0
	currGroupsInAssignment := 0
	removingUsersInAssignment := 0
	removingGroupsInAssignment := 0

	byScope := filterAssignmentHitsByScope(assignments, ram.teamScope, ram.objectScope)

	for _, a := range byScope {
		// Increase counts of users,groups in specified role
		if a.PrincipalRef.Kind == PrincipalUser {
			currUsersInAssignment++
			if slices.Contains(users, a.PrincipalRef.ID) {
				removingUsersInAssignment++
			}
		}
		if a.PrincipalRef.Kind == PrincipalGroup {
			currGroupsInAssignment++
			if slices.Contains(users, a.PrincipalRef.ID) {
				removingGroupsInAssignment++
			}
		}
	}

	if r.Kind != nil {
		if *r.Kind == PrincipalUser && currUsersInAssignment == removingUsersInAssignment {
			return fmt.Errorf("must have a least %v user assigned to role: %s", r.Min, r.RoleID)
		}

		if *r.Kind == PrincipalGroup && currGroupsInAssignment == removingGroupsInAssignment {
			return fmt.Errorf("must have a least %v group assigned to role: %s", r.Min, r.RoleID)
		}

		return nil
	}

	if currGroupsInAssignment == removingGroupsInAssignment && currUsersInAssignment == removingUsersInAssignment {
		return fmt.Errorf("must have a least %v user or group assigned to role: %s", r.Min, r.RoleID)
	}

	return nil
}

func filterAssignmentHitsByScope(hits []RoleAssignmentHit, teamScope *string, objScope *string) []RoleAssignmentHit {
	filtered := []RoleAssignmentHit{}

	for _, hit := range hits {
		// Filter based on team scope
		if teamScope != nil && *teamScope != "*" {
			teamVal, ok := hit.BindingValues["team"]
			if !ok {
				continue
			}
			if *teamScope != teamVal {
				continue
			}
		}

		// Filter based on object scope
		if objScope != nil && *objScope != "*" {
			objVal, ok := hit.BindingValues["object"]
			if !ok {
				continue
			}
			if *objScope != objVal {
				continue
			}
		}

		filtered = append(filtered, hit)
	}

	return filtered
}

func filterAssignmentsByScope(roleAssignments []RoleAssignment, teamScope *string, objScope *string) []RoleAssignment {
	filtered := []RoleAssignment{}

	for _, ra := range roleAssignments {
		// Filter based on team scope
		if teamScope != nil && *teamScope != "*" {
			teamVal, ok := ra.BindingValues["team"]
			if !ok {
				continue
			}
			if *teamScope != teamVal {
				continue
			}
		}

		// Filter based on object scope
		if objScope != nil && *objScope != "*" {
			objVal, ok := ra.BindingValues["object"]
			if !ok {
				continue
			}
			if *objScope != objVal {
				continue
			}
		}

		filtered = append(filtered, ra)
	}

	return filtered
}
