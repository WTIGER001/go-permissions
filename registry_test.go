package permissions

import "testing"

func TestPermissionRegistry_RegisterGetList(t *testing.T) {
	r := NewPermissionRegistry()

	def := PermissionDefinition{
		ID:          "billing.read",
		Scope:       PermissionScopeTeam,
		Namespace:   "Billing",
		Name:        "Read Billing",
		Description: "Allows reading billing data.",
		Fields:      []string{"amount", "currency"},
	}

	if err := r.Register(def); err != nil {
		t.Fatalf("register permission: %v", err)
	}

	got, ok := r.Get(def.ID)
	if !ok {
		t.Fatalf("expected permission to exist")
	}

	if got.ID != def.ID {
		t.Fatalf("expected ID %q, got %q", def.ID, got.ID)
	}

	if got.Scope != PermissionScopeTeam {
		t.Fatalf("expected team scope, got %q", got.Scope)
	}

	if len(r.List()) != 1 {
		t.Fatalf("expected one permission in registry")
	}

	if !r.Exists(def.ID) {
		t.Fatalf("expected Exists to return true")
	}

	// Ensure callers cannot mutate internal registry state through returned slices.
	got.Fields[0] = "mutated"
	reloaded, ok := r.Get(def.ID)
	if !ok {
		t.Fatalf("expected permission to exist after reload")
	}
	if reloaded.Fields[0] != "amount" {
		t.Fatalf("expected registry field to remain unchanged, got %q", reloaded.Fields[0])
	}
}

func TestPermissionRegistry_RejectsDuplicateIDs(t *testing.T) {
	r := NewPermissionRegistry()

	def := PermissionDefinition{
		ID:          "projects.view",
		Scope:       PermissionScopeSystem,
		Namespace:   "Projects",
		Name:        "View Projects",
		Description: "Allows listing projects.",
	}

	if err := r.Register(def); err != nil {
		t.Fatalf("first register should succeed: %v", err)
	}

	if err := r.Register(def); err == nil {
		t.Fatalf("expected duplicate register to fail")
	}
}

func TestPermissionRegistry_ListByNamespace(t *testing.T) {
	r := NewPermissionRegistry()

	r.MustRegister(PermissionDefinition{
		ID:        "billing.read",
		Scope:     PermissionScopeTeam,
		Namespace: "Billing",
		Name:      "Read Billing",
	})
	r.MustRegister(PermissionDefinition{
		ID:        "billing.write",
		Scope:     PermissionScopeTeam,
		Namespace: "Billing",
		Name:      "Write Billing",
	})
	r.MustRegister(PermissionDefinition{
		ID:        "users.view",
		Scope:     PermissionScopeSystem,
		Namespace: "Users",
		Name:      "View Users",
	})

	billing := r.ListByNamespace("Billing")
	if len(billing) != 2 {
		t.Fatalf("expected 2 billing permissions, got %d", len(billing))
	}

	if billing[0].ID != "billing.read" || billing[1].ID != "billing.write" {
		t.Fatalf("expected sorted billing permissions, got %+v", billing)
	}
}

func TestPermissionDefinitionFromPermissionTypes(t *testing.T) {
	systemDef := NewSystemPermission("system.audit.view", "Audit", "View Audit", "Allows reading audit logs.").
		WithFields([]string{"id", "timestamp"}).
		Definition()

	if systemDef.Scope != PermissionScopeSystem {
		t.Fatalf("expected system scope, got %q", systemDef.Scope)
	}
	if systemDef.ID != "system.audit.view" {
		t.Fatalf("unexpected ID %q", systemDef.ID)
	}

	teamDef := NewTeamPermission("billing.read", "Billing", "Read Billing", "Allows reading billing data.").Definition()
	if teamDef.Scope != PermissionScopeTeam {
		t.Fatalf("expected team scope, got %q", teamDef.Scope)
	}

	objectDef := NewObjectPermission("file.read", "Files", "Read File", "Allows reading a file.").Definition()
	if objectDef.Scope != PermissionScopeObject {
		t.Fatalf("expected object scope, got %q", objectDef.Scope)
	}
}
