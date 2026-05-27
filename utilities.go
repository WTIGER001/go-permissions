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
	id          string
	namespace   string
	name        string
	description string
	fields      []string
	checker     Checker
}

func newPermissionMeta(id, namespace, name, description string) permissionMeta {
	return permissionMeta{
		id:          id,
		namespace:   namespace,
		name:        name,
		description: description,
	}
}

func (m *permissionMeta) ID() string                  { return m.id }
func (m *permissionMeta) Namespace() string           { return m.namespace }
func (m *permissionMeta) Name() string                { return m.name }
func (m *permissionMeta) Description() string         { return m.description }
func (m *permissionMeta) Fields() []string            { return append([]string(nil), m.fields...) }
func (m *permissionMeta) withChecker(checker Checker) { m.checker = checker }
func (m *permissionMeta) withFields(fields []string)  { m.fields = append([]string(nil), fields...) }

func (m *permissionMeta) ensureChecker() error {
	if m.checker == nil {
		return fmt.Errorf("permission %q has no checker configured", m.id)
	}
	return nil
}

type SystemPermission struct{ permissionMeta }

func NewSystemPermission(id, namespace, name, description string) *SystemPermission {
	return &SystemPermission{permissionMeta: newPermissionMeta(id, namespace, name, description)}
}

func (p *SystemPermission) WithChecker(checker Checker) *SystemPermission {
	p.withChecker(checker)
	return p
}
func (p *SystemPermission) WithFields(fields []string) *SystemPermission {
	p.withFields(fields)
	return p
}

func (p *SystemPermission) Can(ctx context.Context, subject any) bool {
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	return p.CanUserID(ctx, userID)
}

func (p *SystemPermission) CanUserID(ctx context.Context, userID string) bool {
	if err := p.ensureChecker(); err != nil {
		return false
	}
	ok, err := p.checker.HasPermission(ctx, Request{UserID: userID, Perm: p.id})
	if err != nil {
		return false
	}

	return ok
}

type TeamPermission struct{ permissionMeta }

func NewTeamPermission(id, namespace, name, description string) *TeamPermission {
	return &TeamPermission{permissionMeta: newPermissionMeta(id, namespace, name, description)}
}

func (p *TeamPermission) WithChecker(checker Checker) *TeamPermission {
	p.withChecker(checker)
	return p
}
func (p *TeamPermission) WithFields(fields []string) *TeamPermission { p.withFields(fields); return p }

func (p *TeamPermission) Can(ctx context.Context, subject any, teamID int64) bool {
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	return p.CanUserID(ctx, userID, teamID)
}

func (p *TeamPermission) CanUserID(ctx context.Context, userID string, teamID int64) bool {
	if err := p.ensureChecker(); err != nil {
		return false
	}
	ok, err := p.checker.HasPermission(ctx, Request{UserID: userID, TeamID: &teamID, Perm: p.id})
	if err != nil {
		return false
	}

	return ok
}

func (p *TeamPermission) Any(ctx context.Context, subject any, teamIDs ...int64) bool {
	if len(teamIDs) == 0 {
		return false
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	for _, teamID := range teamIDs {
		ok := p.CanUserID(ctx, userID, teamID)
		if ok {
			return true
		}
	}
	return false
}

func (p *TeamPermission) All(ctx context.Context, subject any, teamIDs ...int64) bool {
	if len(teamIDs) == 0 {
		return true
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	for _, teamID := range teamIDs {
		ok := p.CanUserID(ctx, userID, teamID)
		if !ok {
			return false
		}
	}
	return true
}

func (p *TeamPermission) Filter(ctx context.Context, subject any, teamIDs ...int64) []int64 {
	if len(teamIDs) == 0 {
		return []int64{}
	}
	userID, err := subjectID(subject)
	if err != nil {
		return []int64{}
	}
	allowed := make([]int64, 0, len(teamIDs))
	for _, teamID := range teamIDs {
		ok := p.CanUserID(ctx, userID, teamID)
		if ok {
			allowed = append(allowed, teamID)
		}
	}
	return allowed
}

type ObjectPermission struct{ permissionMeta }

func NewObjectPermission(id, namespace, name, description string) *ObjectPermission {
	return &ObjectPermission{permissionMeta: newPermissionMeta(id, namespace, name, description)}
}

func (p *ObjectPermission) WithChecker(checker Checker) *ObjectPermission {
	p.withChecker(checker)
	return p
}
func (p *ObjectPermission) WithFields(fields []string) *ObjectPermission {
	p.withFields(fields)
	return p
}

func (p *ObjectPermission) Can(ctx context.Context, subject any, objectID string) bool {
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	return p.CanUserID(ctx, userID, objectID)
}

func (p *ObjectPermission) CanUserID(ctx context.Context, userID, objectID string) bool {
	if err := p.ensureChecker(); err != nil {
		return false
	}
	if objectID == "" {
		return false
	}
	ok, err := p.checker.HasPermission(ctx, Request{UserID: userID, Object: objectID, Perm: p.id})
	if err != nil {
		return false
	}

	return ok
}

func (p *ObjectPermission) CanHierarchical(ctx context.Context, subject any, leafID string, parentPath ...string) bool {
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	return p.CanHierarchicalUserID(ctx, userID, leafID, parentPath...)
}

func (p *ObjectPermission) CanHierarchicalUserID(ctx context.Context, userID, leafID string, parentPath ...string) bool {
	obj, err := buildHierarchyObject(leafID, parentPath...)
	if err != nil {
		return false
	}
	return p.CanUserID(ctx, userID, obj)
}

func (p *ObjectPermission) Any(ctx context.Context, subject any, objectIDs ...string) bool {
	if len(objectIDs) == 0 {
		return false
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	for _, objectID := range objectIDs {
		ok := p.CanUserID(ctx, userID, objectID)
		if ok {
			return true
		}
	}
	return false
}

func (p *ObjectPermission) All(ctx context.Context, subject any, objectIDs ...string) bool {
	if len(objectIDs) == 0 {
		return true
	}
	userID, err := subjectID(subject)
	if err != nil {
		return false
	}
	for _, objectID := range objectIDs {
		ok := p.CanUserID(ctx, userID, objectID)
		if !ok {
			return false
		}
	}
	return true
}

func (p *ObjectPermission) Filter(ctx context.Context, subject any, objectIDs ...string) []string {
	if len(objectIDs) == 0 {
		return []string{}
	}
	userID, err := subjectID(subject)
	if err != nil {
		return []string{}
	}
	allowed := make([]string, 0, len(objectIDs))
	for _, objectID := range objectIDs {
		ok := p.CanUserID(ctx, userID, objectID)
		if ok {
			allowed = append(allowed, objectID)
		}
	}
	return allowed
}

func (p *ObjectPermission) HierarchicalFilter(ctx context.Context, subject any, leafIDs []string, sharedParentPath []string) []string {
	if len(leafIDs) == 0 {
		return []string{}
	}
	userID, err := subjectID(subject)
	if err != nil {
		return []string{}
	}
	allowed := make([]string, 0, len(leafIDs))
	for _, leafID := range leafIDs {
		ok := p.CanHierarchicalUserID(ctx, userID, leafID, sharedParentPath...)
		if ok {
			allowed = append(allowed, leafID)
		}
	}
	return allowed
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
