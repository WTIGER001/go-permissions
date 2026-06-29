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
	CreateRole(ctx context.Context, role Role) error
	UpdateRole(ctx context.Context, role Role) error
	DeleteRole(ctx context.Context, roleID string) error
	// AddRoleInheritance declares that parentRoleID inherits all permissions of
	// childRoleID. The store must maintain transitive closure so that
	// ExpandRoles returns every transitively inherited role.
	AddRoleInheritance(ctx context.Context, parentRoleID, childRoleID string) error
	RoleAssignmentsForPrincipal(ctx context.Context, principal PrincipalRef) ([]RoleAssignment, error)
	AssignRole(ctx context.Context, principal PrincipalRef, roleID string, bindingValues map[string]any) error
	GrantsForPrincipal(ctx context.Context, principal PrincipalRef) ([]Grant, error)
	GrantsForOwners(ctx context.Context, owners []PrincipalRef, req Request) ([]Grant, error)
	CreateGrant(ctx context.Context, grant Grant) error
	PrincipalsWithGrant(ctx context.Context, req Request) ([]PrincipalHit, error)
	ExpandRoles(ctx context.Context, roleIDs []string) ([]string, error)
	DeleteGrantsForOwner(ctx context.Context, ownerKind PrincipalKind, ownerID string) error
	DisableBuiltInRole(ctx context.Context, roleID string) error
	EnableBuiltInRole(ctx context.Context, roleID string) error
	DisabledBuiltInRoles(ctx context.Context) ([]string, error)
}

// BulkGrantStore is an optional extension for stores that can write many grants efficiently.
// Service methods can detect this interface and use transactional/batched inserts.
type BulkGrantStore interface {
	CreateGrants(ctx context.Context, grants []Grant) error
}
