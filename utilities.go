package permissions

import (
	"context"
	"fmt"
	"strings"
)

type Checker interface {
	HasPermission(ctx context.Context, req Request) (bool, error)
}

type Subject interface {
	PermissionSubjectID() string
}

type StringSubject string

func (s StringSubject) PermissionSubjectID() string {
	return string(s)
}

type permissionMeta struct {
	id           string
	namespace    string
	name         string
	description  string
	adminAllowed bool
	fields       []string
	checker      Checker
}

func newPermissionMeta(id, namespace, name, description string, adminAllowed bool) permissionMeta {
	return permissionMeta{
		id:           id,
		namespace:    namespace,
		name:         name,
		description:  description,
		adminAllowed: adminAllowed,
	}
}

func (m *permissionMeta) ID() string                  { return m.id }
func (m *permissionMeta) Namespace() string           { return m.namespace }
func (m *permissionMeta) Name() string                { return m.name }
func (m *permissionMeta) Description() string         { return m.description }
func (m *permissionMeta) AdminAllowed() bool          { return m.adminAllowed }
func (m *permissionMeta) Fields() []string            { return append([]string(nil), m.fields...) }
func (m *permissionMeta) withChecker(checker Checker) { m.checker = checker }
func (m *permissionMeta) withoutAdmin()               { m.adminAllowed = false }
func (m *permissionMeta) withFields(fields []string)  { m.fields = append([]string(nil), fields...) }

func (m *permissionMeta) ensureChecker() error {
	if m.checker == nil {
		return fmt.Errorf("permission %q has no checker configured", m.id)
	}
	return nil
}

type SystemPermission struct{ permissionMeta }

func NewSystemPermission(id, namespace, name, description string, adminAllowed bool) *SystemPermission {
	return &SystemPermission{permissionMeta: newPermissionMeta(id, namespace, name, description, adminAllowed)}
}

func (p *SystemPermission) WithChecker(checker Checker) *SystemPermission {
	p.withChecker(checker)
	return p
}
func (p *SystemPermission) WithoutAdmin() *SystemPermission { p.withoutAdmin(); return p }
func (p *SystemPermission) WithFields(fields []string) *SystemPermission {
	p.withFields(fields)
	return p
}

func (p *SystemPermission) Can(ctx context.Context, subject any) (bool, error) {
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	return p.CanUserID(ctx, userID)
}

func (p *SystemPermission) CanUserID(ctx context.Context, userID string) (bool, error) {
	if err := p.ensureChecker(); err != nil {
		return false, err
	}
	return p.checker.HasPermission(ctx, Request{UserID: userID, Perm: p.id})
}

type TeamPermission struct{ permissionMeta }

func NewTeamPermission(id, namespace, name, description string, adminAllowed bool) *TeamPermission {
	return &TeamPermission{permissionMeta: newPermissionMeta(id, namespace, name, description, adminAllowed)}
}

func (p *TeamPermission) WithChecker(checker Checker) *TeamPermission {
	p.withChecker(checker)
	return p
}
func (p *TeamPermission) WithoutAdmin() *TeamPermission              { p.withoutAdmin(); return p }
func (p *TeamPermission) WithFields(fields []string) *TeamPermission { p.withFields(fields); return p }

func (p *TeamPermission) Can(ctx context.Context, subject any, teamID int64) (bool, error) {
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	return p.CanUserID(ctx, userID, teamID)
}

func (p *TeamPermission) CanUserID(ctx context.Context, userID string, teamID int64) (bool, error) {
	if err := p.ensureChecker(); err != nil {
		return false, err
	}
	return p.checker.HasPermission(ctx, Request{UserID: userID, TeamID: &teamID, Perm: p.id})
}

func (p *TeamPermission) Any(ctx context.Context, subject any, teamIDs ...int64) (bool, error) {
	if len(teamIDs) == 0 {
		return false, nil
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	for _, teamID := range teamIDs {
		ok, err := p.CanUserID(ctx, userID, teamID)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (p *TeamPermission) All(ctx context.Context, subject any, teamIDs ...int64) (bool, error) {
	if len(teamIDs) == 0 {
		return true, nil
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	for _, teamID := range teamIDs {
		ok, err := p.CanUserID(ctx, userID, teamID)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func (p *TeamPermission) Filter(ctx context.Context, subject any, teamIDs ...int64) ([]int64, error) {
	if len(teamIDs) == 0 {
		return []int64{}, nil
	}
	userID, err := subjectID(subject)
	if err != nil {
		return nil, err
	}
	allowed := make([]int64, 0, len(teamIDs))
	for _, teamID := range teamIDs {
		ok, err := p.CanUserID(ctx, userID, teamID)
		if err != nil {
			return nil, err
		}
		if ok {
			allowed = append(allowed, teamID)
		}
	}
	return allowed, nil
}

type ObjectPermission struct{ permissionMeta }

func NewObjectPermission(id, namespace, name, description string, adminAllowed bool) *ObjectPermission {
	return &ObjectPermission{permissionMeta: newPermissionMeta(id, namespace, name, description, adminAllowed)}
}

func (p *ObjectPermission) WithChecker(checker Checker) *ObjectPermission {
	p.withChecker(checker)
	return p
}
func (p *ObjectPermission) WithoutAdmin() *ObjectPermission { p.withoutAdmin(); return p }
func (p *ObjectPermission) WithFields(fields []string) *ObjectPermission {
	p.withFields(fields)
	return p
}

func (p *ObjectPermission) Can(ctx context.Context, subject any, objectID string) (bool, error) {
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	return p.CanUserID(ctx, userID, objectID)
}

func (p *ObjectPermission) CanUserID(ctx context.Context, userID, objectID string) (bool, error) {
	if err := p.ensureChecker(); err != nil {
		return false, err
	}
	if objectID == "" {
		return false, fmt.Errorf("object ID is required")
	}
	return p.checker.HasPermission(ctx, Request{UserID: userID, Object: objectID, Perm: p.id})
}

func (p *ObjectPermission) CanHierarchical(ctx context.Context, subject any, leafID string, parentPath ...string) (bool, error) {
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	return p.CanHierarchicalUserID(ctx, userID, leafID, parentPath...)
}

func (p *ObjectPermission) CanHierarchicalUserID(ctx context.Context, userID, leafID string, parentPath ...string) (bool, error) {
	obj, err := buildHierarchyObject(leafID, parentPath...)
	if err != nil {
		return false, err
	}
	return p.CanUserID(ctx, userID, obj)
}

func (p *ObjectPermission) Any(ctx context.Context, subject any, objectIDs ...string) (bool, error) {
	if len(objectIDs) == 0 {
		return false, nil
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	for _, objectID := range objectIDs {
		ok, err := p.CanUserID(ctx, userID, objectID)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (p *ObjectPermission) All(ctx context.Context, subject any, objectIDs ...string) (bool, error) {
	if len(objectIDs) == 0 {
		return true, nil
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false, err
	}
	for _, objectID := range objectIDs {
		ok, err := p.CanUserID(ctx, userID, objectID)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func (p *ObjectPermission) Filter(ctx context.Context, subject any, objectIDs ...string) ([]string, error) {
	if len(objectIDs) == 0 {
		return []string{}, nil
	}
	userID, err := subjectID(subject)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(objectIDs))
	for _, objectID := range objectIDs {
		ok, err := p.CanUserID(ctx, userID, objectID)
		if err != nil {
			return nil, err
		}
		if ok {
			allowed = append(allowed, objectID)
		}
	}
	return allowed, nil
}

func (p *ObjectPermission) HierarchicalFilter(ctx context.Context, subject any, leafIDs []string, sharedParentPath []string) ([]string, error) {
	if len(leafIDs) == 0 {
		return []string{}, nil
	}
	userID, err := subjectID(subject)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(leafIDs))
	for _, leafID := range leafIDs {
		ok, err := p.CanHierarchicalUserID(ctx, userID, leafID, sharedParentPath...)
		if err != nil {
			return nil, err
		}
		if ok {
			allowed = append(allowed, leafID)
		}
	}
	return allowed, nil
}

func subjectID(subject any) (string, error) {
	switch v := subject.(type) {
	case string:
		if v == "" {
			return "", fmt.Errorf("subject ID is required")
		}
		return v, nil
	case StringSubject:
		if v == "" {
			return "", fmt.Errorf("subject ID is required")
		}
		return string(v), nil
	case Subject:
		id := v.PermissionSubjectID()
		if id == "" {
			return "", fmt.Errorf("subject ID is required")
		}
		return id, nil
	case interface{ SubjectID() string }:
		id := v.SubjectID()
		if id == "" {
			return "", fmt.Errorf("subject ID is required")
		}
		return id, nil
	default:
		return "", fmt.Errorf("unsupported subject type %T", subject)
	}
}

func buildHierarchyObject(leafID string, parentPath ...string) (string, error) {
	if leafID == "" {
		return "", fmt.Errorf("leaf ID is required")
	}
	parts := make([]string, 0, 1+len(parentPath))
	parts = append(parts, leafID)
	for _, parent := range parentPath {
		if parent == "" {
			return "", fmt.Errorf("parent path entries must be non-empty")
		}
		parts = append(parts, parent)
	}
	return strings.Join(parts, "/"), nil
}
