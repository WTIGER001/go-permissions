package inmemory

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func TestListPrincipalsWithGrant_DenyOverridesAllow(t *testing.T) {
	store := NewStore()
	teamID := "42"
	anyObject := "*"

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectDeny, TeamScope: "42", ObjectScope: &anyObject, PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "r-1", Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "billing.read"},
	)

	hits, err := store.PrincipalsWithGrant(context.Background(), permissions.Request{
		TeamID: teamID,
		Object: "billing",
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("PrincipalsWithGrant: %v", err)
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
