package permissions

import "context"

type IdentityProvider interface {
	GetUserGroups(ctx context.Context, userID string) ([]string, error)
	GetGroupMembers(ctx context.Context, groupID string) ([]string, error)
	IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error)
}

type PermissionStore interface {
	RoleDefinitions(ctx context.Context) ([]Role, error)
	RoleDefinition(ctx context.Context, roleID string) (Role, error)
	RoleAssignmentsForPrincipal(ctx context.Context, principal PrincipalRef) ([]RoleAssignment, error)
	GrantsForPrincipal(ctx context.Context, principal PrincipalRef) ([]Grant, error)
	GrantsForOwners(ctx context.Context, owners []PrincipalRef, req Request) ([]Grant, error)
	PrincipalsWithGrant(ctx context.Context, req Request) ([]PrincipalHit, error)
	ExpandRoles(ctx context.Context, roleIDs []string) ([]string, error)
}

// GrantWriter is an optional store capability for creating policy grants.
type GrantWriter interface {
	CreateGrant(ctx context.Context, grant Grant) error
}

// RoleAssignmentWriter is an optional store capability for assigning roles to principals.
type RoleAssignmentWriter interface {
	AssignRole(ctx context.Context, principal PrincipalRef, roleID string, bindingValues map[string]any) error
}
