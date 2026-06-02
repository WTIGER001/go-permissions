package jsonstore

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func TestJSONStore_SaveLoadAndHasPermission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissions.json")

	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	anyObject := "*"
	if err := store.SetData(Data{
		UserGroups: map[string][]string{
			"u-1": {"g-1"},
		},
		Grants: []permissions.Grant{
			{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
			{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectDeny, TeamScope: "42", ObjectScope: &anyObject, PermissionName: "billing.read"},
		},
	}); err != nil {
		t.Fatalf("set data: %v", err)
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}

	teamID := int64(42)
	svc := permissions.NewService(reloaded, reloaded)
	allowed, err := svc.HasPermission(context.Background(), permissions.Request{
		UserID: "u-1",
		TeamID: &teamID,
		Object: "billing",
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("HasPermission returned error: %v", err)
	}
	if allowed {
		t.Fatalf("expected deny to override allow")
	}
}

func TestJSONStore_ListPrincipalsWithGrant_DenyOverridesAllow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissions.json")

	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	anyObject := "*"
	if err := store.SetData(Data{
		Grants: []permissions.Grant{
			{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
			{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
			{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectDeny, TeamScope: "42", ObjectScope: &anyObject, PermissionName: "billing.read"},
			{OwnerKind: permissions.PrincipalRole, OwnerID: "r-1", Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "billing.read"},
		},
	}); err != nil {
		t.Fatalf("set data: %v", err)
	}

	teamID := int64(42)
	hits, err := store.ListPrincipalsWithGrant(context.Background(), permissions.Request{TeamID: &teamID, Object: "billing", Perm: "billing.read"})
	if err != nil {
		t.Fatalf("ListPrincipalsWithGrant: %v", err)
	}

	got := make([]string, 0, len(hits))
	for _, hit := range hits {
		got = append(got, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(got)

	expected := []string{"role:r-1", "user:u-1"}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

func TestJSONStore_TransitiveRoleInheritance(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "permissions.json")

	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	// Build r-top -> r-mid -> r-leaf.
	if err := store.AddRoleInheritance(ctx, "r-top", "r-mid"); err != nil {
		t.Fatalf("AddRoleInheritance r-top->r-mid: %v", err)
	}
	if err := store.AddRoleInheritance(ctx, "r-mid", "r-leaf"); err != nil {
		t.Fatalf("AddRoleInheritance r-mid->r-leaf: %v", err)
	}

	// ExpandRoles from r-top should return r-top, r-mid, r-leaf.
	expanded, err := store.ExpandRoles(ctx, []string{"r-top"})
	if err != nil {
		t.Fatalf("ExpandRoles: %v", err)
	}
	sort.Strings(expanded)
	want := []string{"r-leaf", "r-mid", "r-top"}
	if !reflect.DeepEqual(expanded, want) {
		t.Fatalf("expected expanded roles %v, got %v", want, expanded)
	}

	// Reload from disk and verify the expansion is still correct.
	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	expanded2, err := reloaded.ExpandRoles(ctx, []string{"r-top"})
	if err != nil {
		t.Fatalf("ExpandRoles after reload: %v", err)
	}
	sort.Strings(expanded2)
	if !reflect.DeepEqual(expanded2, want) {
		t.Fatalf("after reload: expected %v, got %v", want, expanded2)
	}
}
