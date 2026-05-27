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
	ListPrincipalsWithGrant(ctx context.Context, req Request) ([]PrincipalHit, error)
}

type Store interface {
	IdentityResolver
	PolicyStore
}

// GrantWriter is an optional store capability for creating policy grants.
type GrantWriter interface {
	CreateGrant(ctx context.Context, grant Grant) error
}

// RoleAssignmentWriter is an optional store capability for assigning roles to principals.
type RoleAssignmentWriter interface {
	AssignRole(ctx context.Context, principal PrincipalRef, roleID string, bindingValues map[string]any) error
}
