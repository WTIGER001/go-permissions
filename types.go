package permissions

import "fmt"

type PrincipalKind string

const (
	PrincipalUser  PrincipalKind = "user"
	PrincipalGroup PrincipalKind = "group"
	PrincipalRole  PrincipalKind = "role"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Request struct {
	UserID string
	TeamID *int64
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

type Grant struct {
	ID             int64
	OwnerKind      PrincipalKind
	OwnerID        string
	Effect         Effect
	TeamScope      string
	ObjectScope    *string
	PermissionName string
	FieldAllowlist []string
	VariableSpec   map[string]any
}

type EffectivePermission struct {
	TeamScope      string
	ObjectScope    *string
	PermissionName string
	Source         PrincipalRef
	Effect         Effect
	Fields         []string
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
