package permissions

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type PermissionScope string

const (
	PermissionScopeSystem PermissionScope = "system"
	PermissionScopeTeam   PermissionScope = "team"
	PermissionScopeObject PermissionScope = "object"
)

type PermissionDefinition struct {
	ID           string
	Scope        PermissionScope
	Namespace    string
	Name         string
	Description  string
	AdminAllowed bool
	Fields       []string
}

func (d PermissionDefinition) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("permission ID is required")
	}
	if d.Scope != PermissionScopeSystem && d.Scope != PermissionScopeTeam && d.Scope != PermissionScopeObject {
		return fmt.Errorf("permission scope must be one of %q, %q, %q", PermissionScopeSystem, PermissionScopeTeam, PermissionScopeObject)
	}
	if strings.TrimSpace(d.Namespace) == "" {
		return fmt.Errorf("permission namespace is required")
	}
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("permission name is required")
	}
	return nil
}

func (d PermissionDefinition) clone() PermissionDefinition {
	copyDef := d
	copyDef.Fields = append([]string(nil), d.Fields...)
	return copyDef
}

type PermissionRegistry struct {
	mu   sync.RWMutex
	byID map[string]PermissionDefinition
}

func NewPermissionRegistry() *PermissionRegistry {
	return &PermissionRegistry{
		byID: make(map[string]PermissionDefinition),
	}
}

func (r *PermissionRegistry) Register(def PermissionDefinition) error {
	if err := def.Validate(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byID[def.ID]; exists {
		return fmt.Errorf("permission %q is already registered", def.ID)
	}

	r.byID[def.ID] = def.clone()
	return nil
}

func (r *PermissionRegistry) MustRegister(def PermissionDefinition) {
	if err := r.Register(def); err != nil {
		panic(err)
	}
}

func (r *PermissionRegistry) Get(permissionID string) (PermissionDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	def, ok := r.byID[permissionID]
	if !ok {
		return PermissionDefinition{}, false
	}

	return def.clone(), true
}

func (r *PermissionRegistry) Exists(permissionID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.byID[permissionID]
	return ok
}

func (r *PermissionRegistry) List() []PermissionDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PermissionDefinition, 0, len(r.byID))
	for _, def := range r.byID {
		result = append(result, def.clone())
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

func (r *PermissionRegistry) ListByNamespace(namespace string) []PermissionDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PermissionDefinition, 0)
	for _, def := range r.byID {
		if def.Namespace == namespace {
			result = append(result, def.clone())
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

func (r *PermissionRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.byID)
}

func (p *SystemPermission) Definition() PermissionDefinition {
	return PermissionDefinition{
		ID:           p.ID(),
		Scope:        PermissionScopeSystem,
		Namespace:    p.Namespace(),
		Name:         p.Name(),
		Description:  p.Description(),
		AdminAllowed: p.AdminAllowed(),
		Fields:       p.Fields(),
	}
}

func (p *TeamPermission) Definition() PermissionDefinition {
	return PermissionDefinition{
		ID:           p.ID(),
		Scope:        PermissionScopeTeam,
		Namespace:    p.Namespace(),
		Name:         p.Name(),
		Description:  p.Description(),
		AdminAllowed: p.AdminAllowed(),
		Fields:       p.Fields(),
	}
}

func (p *ObjectPermission) Definition() PermissionDefinition {
	return PermissionDefinition{
		ID:           p.ID(),
		Scope:        PermissionScopeObject,
		Namespace:    p.Namespace(),
		Name:         p.Name(),
		Description:  p.Description(),
		AdminAllowed: p.AdminAllowed(),
		Fields:       p.Fields(),
	}
}
