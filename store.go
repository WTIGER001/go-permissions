package permissions

import "context"

type IdentityResolver interface {
	IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error)
}

type PolicyStore interface {
	ListKnownGroupIDs(ctx context.Context) ([]string, error)
	ListRoleAssignmentsForUserAndGroups(ctx context.Context, userID string, groupIDs []string) ([]RoleAssignment, error)
	ListExpandedRoleIDs(ctx context.Context, roleIDs []string) ([]string, error)
	ListGrantsForOwners(ctx context.Context, owners []PrincipalRef, req Request) ([]Grant, error)
}

type Store interface {
	IdentityResolver
	PolicyStore
}
