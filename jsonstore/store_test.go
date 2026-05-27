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
	svc := permissions.NewService(reloaded)
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
