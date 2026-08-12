package permissions

import (
	"context"
	"fmt"
)

type exampleIdentityAdapter struct {
	groupMembership map[string]map[string]bool
}

func (a exampleIdentityAdapter) GetUserGroups(_ context.Context, userID string) ([]string, error) {
	groups, ok := a.groupMembership[userID]
	if !ok {
		return nil, nil
	}

	result := make([]string, 0, len(groups))
	for groupID, member := range groups {
		if member {
			result = append(result, groupID)
		}
	}

	return result, nil
}

func (a exampleIdentityAdapter) GetGroupMembers(_ context.Context, groupID string) ([]string, error) {
	users := make([]string, 0)
	for userID, groups := range a.groupMembership {
		if groups[groupID] {
			users = append(users, userID)
		}
	}

	return users, nil
}

func (a exampleIdentityAdapter) IsUserInGroup(_ context.Context, userID, groupID string) (bool, error) {
	groups, ok := a.groupMembership[userID]
	if !ok {
		return false, nil
	}
	return groups[groupID], nil
}

type examplePolicyStore struct{}

func (examplePolicyStore) RoleDefinitions(_ context.Context) ([]Role, error) {
	return []Role{}, nil
}

func (examplePolicyStore) RoleDefinition(_ context.Context, roleID string) (Role, error) {
	return Role{ID: roleID, Name: roleID}, nil
}

func (examplePolicyStore) RoleAssignmentsForPrincipal(_ context.Context, _ PrincipalRef) ([]RoleAssignment, error) {
	return nil, nil
}

func (examplePolicyStore) ExpandRoles(_ context.Context, roleIDs []string) ([]string, error) {
	return append([]string(nil), roleIDs...), nil
}

func (examplePolicyStore) GrantsForPrincipal(ctx context.Context, principal PrincipalRef) ([]Grant, error) {
	return examplePolicyStore{}.GrantsForOwners(ctx, []PrincipalRef{principal}, Request{})
}

func (examplePolicyStore) GrantsForOwners(_ context.Context, owners []PrincipalRef, req Request) ([]Grant, error) {
	if req.Perm != "billing.read" {
		return nil, nil
	}

	teamscope := "*"
	if req.TeamID != "" {
		teamscope = req.TeamID
	}

	for _, owner := range owners {
		if owner.Kind == PrincipalGroup && owner.ID == "g-finops" {
			return []Grant{{
				OwnerKind:      PrincipalGroup,
				OwnerID:        "g-finops",
				Effect:         EffectAllow,
				TeamScope:      teamscope,
				PermissionName: "billing.read",
			}}, nil
		}
	}

	return nil, nil
}

func (examplePolicyStore) PrincipalsWithGrant(_ context.Context, _ Request) ([]PrincipalHit, error) {
	return nil, nil
}

func (examplePolicyStore) CreateGrant(_ context.Context, _ Grant) error { return nil }
func (examplePolicyStore) AssignRole(_ context.Context, _ PrincipalRef, _ string, _ map[string]any) error {
	return nil
}
func (examplePolicyStore) UnassignRole(_ context.Context, _ PrincipalRef, _ string, _ map[string]any) error {
	return nil
}
func (examplePolicyStore) CreateRole(_ context.Context, _ Role) error              { return nil }
func (examplePolicyStore) UpdateRole(_ context.Context, _ Role) error              { return nil }
func (examplePolicyStore) DeleteRole(_ context.Context, _ string) error            { return nil }
func (examplePolicyStore) AddRoleInheritance(_ context.Context, _, _ string) error { return nil }
func (examplePolicyStore) DeleteGrantsForOwner(_ context.Context, _ PrincipalKind, _ string) error {
	return nil
}
func (examplePolicyStore) DisableBuiltInRole(_ context.Context, _ string) error { return nil }
func (examplePolicyStore) EnableBuiltInRole(_ context.Context, _ string) error  { return nil }
func (e examplePolicyStore) DisabledBuiltInRoles(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

func (e examplePolicyStore) ListGrants(ctx context.Context, query GrantQuery) (GrantQueryResult, error) {
	return GrantQueryResult{}, nil
}

func ExampleNewServiceWithIdentity_customIdentityAdapter() {
	identity := exampleIdentityAdapter{
		groupMembership: map[string]map[string]bool{
			"u-123": {"g-finops": true},
		},
	}
	policy := examplePolicyStore{}

	svc := NewServiceWithIdentity(identity, policy)
	teamID := "42"

	ok, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-123",
		TeamID: teamID,
		Perm:   "billing.read",
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(ok)
	// Output: true
}
