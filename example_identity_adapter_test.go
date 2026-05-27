package permissions

import (
	"context"
	"fmt"
)

type exampleIdentityAdapter struct {
	groupMembership map[string]map[string]bool
}

func (a exampleIdentityAdapter) IsUserInGroup(_ context.Context, userID, groupID string) (bool, error) {
	groups, ok := a.groupMembership[userID]
	if !ok {
		return false, nil
	}
	return groups[groupID], nil
}

type examplePolicyStore struct{}

func (examplePolicyStore) ListKnownGroupIDs(_ context.Context) ([]string, error) {
	return []string{"g-finops"}, nil
}

func (examplePolicyStore) ListRoleAssignmentsForUserAndGroups(_ context.Context, _ string, _ []string) ([]RoleAssignment, error) {
	return nil, nil
}

func (examplePolicyStore) ListExpandedRoleIDs(_ context.Context, _ []string) ([]string, error) {
	return nil, nil
}

func (examplePolicyStore) ListGrantsForOwners(_ context.Context, owners []PrincipalRef, req Request) ([]Grant, error) {
	for _, owner := range owners {
		if owner.Kind == PrincipalGroup && owner.ID == "g-finops" && req.Perm == "billing.read" {
			return []Grant{{
				OwnerKind:      PrincipalGroup,
				OwnerID:        "g-finops",
				Effect:         EffectAllow,
				TeamScope:      "42",
				PermissionName: "billing.read",
			}}, nil
		}
	}
	return nil, nil
}

func ExampleNewServiceWithResolvers_customIdentityAdapter() {
	identity := exampleIdentityAdapter{
		groupMembership: map[string]map[string]bool{
			"u-123": {"g-finops": true},
		},
	}
	policy := examplePolicyStore{}

	svc := NewServiceWithIdentity(identity, policy)
	teamID := int64(42)

	ok, err := svc.HasPermission(context.Background(), Request{
		UserID: "u-123",
		TeamID: &teamID,
		Perm:   "billing.read",
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(ok)
	// Output: true
}
