package permissions

import (
	"fmt"
	"strings"
	"time"
)

type RoleScope string

const (
	RoleScopeSystem RoleScope = "system"
	RoleScopeTeam   RoleScope = "team"
	RoleScopeObject RoleScope = "object"
)

type PrincipalKind string

const (
	PrincipalUser  PrincipalKind = "user"
	PrincipalGroup PrincipalKind = "group"
	PrincipalRole  PrincipalKind = "role"
)

const (
	SyntheticRolePublic        = "builtin.public"
	SyntheticRoleAuthenticated = "builtin.authenticated"
	SyntheticRoleAdmin         = "builtin.admin"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Request struct {
	UserID string
	TeamID string
	Object string
	Perm   string
}

type PrincipalRef struct {
	Kind PrincipalKind
	ID   string
}

type RoleAssignment struct {
	RoleID        string
	BindingValues map[string]any
}

type RoleAssignmentHit struct {
	RoleID        string
	BindingValues map[string]any
	PrincipalRef
}

type Grant struct {
	ID               int64
	OwnerKind        PrincipalKind
	OwnerID          string
	Effect           Effect
	TeamScope        string
	ObjectScope      *string
	PermissionName   string
	ExpiresAt        *time.Time
	RestrictedFields []string
	VariableSpec     map[string]any
}

func (g Grant) IsActiveAt(now time.Time) bool {
	if g.ExpiresAt == nil {
		return true
	}
	return now.Before(*g.ExpiresAt)
}

func (g Grant) IsExpiredAt(now time.Time) bool {
	return !g.IsActiveAt(now)
}

type EffectivePermission struct {
	TeamScope        string
	ObjectScope      *string
	PermissionName   string
	Source           PrincipalRef
	Effect           Effect
	RestrictedFields []string
}

type PrincipalHit struct {
	Kind           PrincipalKind
	ID             string
	TeamScope      string
	ObjectScope    *string
	PermissionName string
}

func (r PrincipalRef) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("principal ID is required")
	}
	switch r.Kind {
	case PrincipalUser, PrincipalGroup, PrincipalRole:
		return nil
	default:
		return fmt.Errorf("unsupported principal kind: %q", r.Kind)
	}
}

type Role struct {
	ID           string
	Name         string
	Description  string
	Scope        RoleScope
	Tags         []string
	VariableSpec map[string]any
	Permissions  []string
	BuiltIn      bool
	IsDisabled   bool
}

func (r Role) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("role ID is required")
	}
	if r.Scope != "" && r.Scope != RoleScopeSystem && r.Scope != RoleScopeTeam && r.Scope != RoleScopeObject {
		return fmt.Errorf("invalid role scope: %q", r.Scope)
	}
	return nil
}

type PermissionSource struct {
	Kind    PrincipalKind
	ID      string
	GrantID *int64
	RoleID  *string
}

type PermissionReport struct {
	Principal        PrincipalRef
	TeamScope        string
	ObjectScope      *string
	PermissionName   string
	Effect           Effect
	RestrictedFields []string
	IsDirect         bool
	Sources          []PermissionSource
}

type GrantQuery struct {
	Principals       []PrincipalRef
	TeamScopes       []string
	ObjectScopes     []string
	Permissions      []string
	PermissionPrefix string
	IncludeEffective bool
	Limit            int
	Cursor           string
}

type GrantQueryResult struct {
	Grants     []Grant
	NextCursor string
	TotalCount int
}

type ReportQueryResult struct {
	Reports    []PermissionReport
	NextCursor string
	TotalCount int
}
