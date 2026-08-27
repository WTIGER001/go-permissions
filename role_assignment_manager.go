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
	ValidateAssignment(current []RoleAssignment, proposed []RoleAssignment, manager *roleAssignmentManagerBase) error
}

func (m *RoleAssignmentManager) AddRemovalRule(rule PrincipalRemovalRule) {
	m.removeRules = append(m.removeRules, rule)
}

func (m *RoleAssignmentManager) AddAssignmentRule(rule RoleAssignmentRule) {
	m.assignmentRules = append(m.assignmentRules, rule)
}

// Instantiates an instance of a new Role Assignment manager. This is meant to be used and disposed of quickly.
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
func (m *RoleAssignmentManager) canMakeAssignmentChange(ctx context.Context, principal PrincipalRef, desired []string) error {
	currentAssignments, err := m.service.RoleAssignmentsForPrincipal(ctx, principal)
	if err != nil {
		return err
	}

	add, remove, err := m.computeProposed(ctx, principal, desired)
	if err != nil {
		return err
	}

	proposed := []RoleAssignment{}
	// Build proposed list: current minus removed plus added
	for _, c := range currentAssignments {
		if !contains(remove, c.RoleID) {
			proposed = append(proposed, c)
		}
	}
	for _, a := range add {
		proposed = append(proposed, RoleAssignment{RoleID: a})
	}

	for _, rule := range m.assignmentRules {
		if err := rule.ValidateAssignment(currentAssignments, proposed, &m.roleAssignmentManagerBase); err != nil {
			return err
		}
	}

	return nil
}

func (m *RoleAssignmentManager) CanAddRoles(
	ctx context.Context,
	principal PrincipalRef,
	add []string,
) error {
	current, err := m.service.RoleAssignmentsForPrincipal(ctx, principal)
	if err != nil {
		return err
	}

	desired := []string{}
	for _, c := range current {
		desired = append(desired, c.RoleID)
	}
	desired = append(desired, add...)

	return m.canMakeAssignmentChange(ctx, principal, desired)
}

func (m *RoleAssignmentManager) AddRoles(
	ctx context.Context,
	principal PrincipalRef,
	roles []string,
) error {

	// First verify the change is allowed
	if err := m.CanAddRoles(ctx, principal, roles); err != nil {
		return err
	}

	// Apply additions
	for _, roleID := range roles {
		if err := m.assignRole(ctx, principal, roleID); err != nil {
			return err
		}
	}

	return nil
}

func (m *RoleAssignmentManager) CanRemoveRoles(
	ctx context.Context,
	principal PrincipalRef,
	remove []string,
) error {
	current, err := m.service.RoleAssignmentsForPrincipal(ctx, principal)
	if err != nil {
		return err
	}

	desired := []string{}
	for _, c := range current {
		if !contains(remove, c.RoleID) {
			desired = append(desired, c.RoleID)
		}
	}

	return m.canMakeAssignmentChange(ctx, principal, desired)
}

func (m *RoleAssignmentManager) RemoveRoles(
	ctx context.Context,
	principal PrincipalRef,
	roles []string,
) error {

	// First verify the change is allowed
	if err := m.CanRemoveRoles(ctx, principal, roles); err != nil {
		return err
	}

	// Apply removals
	for _, roleID := range roles {
		if err := m.unassignRole(ctx, principal, roleID); err != nil {
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

	currentSet := map[string]bool{}
	for _, c := range currentAssignments {
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

func (m *RoleAssignmentManager) RemoveBulkUsers(ctx context.Context, users, groups []string) error {
	err := m.CanRemoveBulkUsers(ctx, users, groups)
	if err != nil {
		return err
	}

	var merr *multierror.Error

	for _, user := range users {
		err := m.RemoveRoles(ctx, PrincipalRef{Kind: PrincipalUser, ID: user}, m.managedRoles)
		if err != nil {
			merr = multierror.Append(merr, merr, err)
		}
	}
	for _, group := range groups {
		err := m.RemoveRoles(ctx, PrincipalRef{Kind: PrincipalGroup, ID: group}, m.managedRoles)
		if err != nil {
			merr = multierror.Append(merr, err)
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

func contains(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// **BUILT-IN RULES**

// Example Rule: must have at least one instance of a role
// Useful for things like: must always have exactly one team.owner role
// or at least one team.viewer, etc.
type MustHaveOneRoleRule struct {
	RoleID string
}

func (r MustHaveOneRoleRule) ValidateAssignment(current []RoleAssignment, proposed []RoleAssignment) error {
	count := 0
	for _, a := range proposed {
		if a.RoleID == r.RoleID {
			count++
		}
	}
	if count < 1 {
		return fmt.Errorf("must have at least one %s role", r.RoleID)
	}
	return nil
}

// Example Rule: prohibit combining two specific roles simultaneously
// Useful for situations where roles conflict, e.g. team.owner and team.guest
// cannot be held at the same time.
type CannotCombineRolesRule struct {
	RoleA string
	RoleB string
}

func (r CannotCombineRolesRule) ValidateAssignment(_ []RoleAssignment, proposed []RoleAssignment) error {
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

// Example Rule: limit the number of instances of a role
// Useful for roles that can only appear once per principal, such as team.owner.
type MaxInstancesRule struct {
	RoleID string
	Max    int
}

func (r MaxInstancesRule) ValidateAssignment(_ []RoleAssignment, proposed []RoleAssignment) error {
	count := 0
	for _, a := range proposed {
		if a.RoleID == r.RoleID {
			count++
		}
	}
	if count > r.Max {
		return fmt.Errorf("role %s cannot appear more than %d times", r.RoleID, r.Max)
	}
	return nil
}

// Example Rule: before removing users, check if at least {min} number of assignments exist for role
type RequireAtLeastRule struct {
	RoleID string
	Min    int
}

func (r RequireAtLeastRule) ValidateRemoval(users []string, groups []string, ram *roleAssignmentManagerBase) error {
	// Get current assignments for the provided roleID
	assignments, err := ram.service.RoleAssignmentsForRoleID(context.TODO(), r.RoleID)
	if err != nil {
		return err
	}

	currUsersInAssignment := 0
	currGroupsInAssignment := 0
	removingUsersInAssignment := 0
	removingGroupsInAssignment := 0

	for _, a := range assignments {
		// Filter based on team scope
		if ram.teamScope != nil && *ram.teamScope != "*" {
			teamVal, ok := a.BindingValues["team"]
			if !ok {
				continue
			}
			if *ram.teamScope != teamVal {
				continue
			}
		}

		// Filter based on object scope
		if ram.objectScope != nil && *ram.objectScope != "*" {
			objVal, ok := a.BindingValues["object"]
			if !ok {
				continue
			}
			if *ram.objectScope != objVal {
				continue
			}
		}

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

	if currGroupsInAssignment == removingGroupsInAssignment && currUsersInAssignment == removingUsersInAssignment {
		return fmt.Errorf("must have a least %v user or group assigned to role: %s", r.Min, r.RoleID)
	}

	return nil
}
