package permissions

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestBootstrapStore_RoleLifecycleAndAssignments(t *testing.T) {
	ctx := context.Background()
	s := newBootstrapStore()

	if err := s.CreateRole(ctx, Role{Name: "missing-id"}); err == nil {
		t.Fatalf("expected missing role ID error")
	}
	if err := s.CreateRole(ctx, Role{ID: "r-1"}); err == nil {
		t.Fatalf("expected missing role name error")
	}

	if err := s.CreateRole(ctx, Role{ID: "r-b", Name: "Role B"}); err != nil {
		t.Fatalf("create role r-b: %v", err)
	}
	if err := s.CreateRole(ctx, Role{ID: "r-a", Name: "Role A"}); err != nil {
		t.Fatalf("create role r-a: %v", err)
	}
	if err := s.CreateRole(ctx, Role{ID: "r-a", Name: "Role A"}); err == nil {
		t.Fatalf("expected duplicate role create error")
	}

	if _, err := s.RoleDefinition(ctx, "missing"); err == nil {
		t.Fatalf("expected missing role definition error")
	}
	roles, err := s.RoleDefinitions(ctx)
	if err != nil {
		t.Fatalf("role definitions: %v", err)
	}
	if len(roles) != 2 || roles[0].ID != "r-a" || roles[1].ID != "r-b" {
		t.Fatalf("expected sorted role definitions, got %+v", roles)
	}

	if err := s.UpdateRole(ctx, Role{ID: "", Name: "bad"}); err == nil {
		t.Fatalf("expected missing update role ID error")
	}
	if err := s.UpdateRole(ctx, Role{ID: "r-a", Name: ""}); err == nil {
		t.Fatalf("expected missing update role name error")
	}
	if err := s.UpdateRole(ctx, Role{ID: "missing", Name: "Missing"}); err == nil {
		t.Fatalf("expected update missing role error")
	}
	if err := s.UpdateRole(ctx, Role{ID: "r-a", Name: "Role A2"}); err != nil {
		t.Fatalf("update role: %v", err)
	}

	if err := s.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"}, "missing", nil); err == nil {
		t.Fatalf("expected assign missing role error")
	}
	if err := s.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: ""}, "r-a", nil); err == nil {
		t.Fatalf("expected invalid principal error")
	}
	if err := s.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"}, "", nil); err == nil {
		t.Fatalf("expected missing role ID assign error")
	}

	binding := map[string]any{"team": 42}
	if err := s.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"}, "r-a", binding); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := s.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"}, "r-a", map[string]any{"team": 42}); err != nil {
		t.Fatalf("dedupe assign role should not fail: %v", err)
	}

	assignments, err := s.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"})
	if err != nil {
		t.Fatalf("role assignments for principal: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("expected deduped assignment count 1, got %d", len(assignments))
	}
	assignments[0].BindingValues["team"] = 99
	again, err := s.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"})
	if err != nil {
		t.Fatalf("role assignments second read: %v", err)
	}
	if again[0].BindingValues["team"] != 42 {
		t.Fatalf("expected assignment deep copy on read")
	}
	if _, err := s.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: ""}); err == nil {
		t.Fatalf("expected invalid principal validation error")
	}

	if err := s.DeleteRole(ctx, ""); err == nil {
		t.Fatalf("expected delete missing role ID error")
	}
	if err := s.DeleteRole(ctx, "missing"); err == nil {
		t.Fatalf("expected delete missing role error")
	}
	if err := s.DeleteRole(ctx, "r-a"); err != nil {
		t.Fatalf("delete role: %v", err)
	}

	afterDelete, err := s.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"})
	if err != nil {
		t.Fatalf("assignments after delete: %v", err)
	}
	if len(afterDelete) != 0 {
		t.Fatalf("expected assignments removed when role deleted")
	}
}

func TestBootstrapStore_GrantQueriesAndPrincipals(t *testing.T) {
	ctx := context.Background()
	s := newBootstrapStore()
	if err := s.CreateRole(ctx, Role{ID: "r-1", Name: "Role 1"}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	expired := time.Now().UTC().Add(-time.Minute)
	obj := "invoice"

	if err := s.CreateGrant(ctx, Grant{}); err == nil {
		t.Fatalf("expected create grant validation error")
	}
	if err := s.CreateGrant(ctx, Grant{OwnerKind: PrincipalUser, OwnerID: "u-1", Effect: EffectAllow, TeamScope: "*", PermissionName: "billing.read"}); err != nil {
		t.Fatalf("create user allow grant: %v", err)
	}
	if err := s.CreateGrant(ctx, Grant{OwnerKind: PrincipalGroup, OwnerID: "g-1", Effect: EffectAllow, TeamScope: "*", PermissionName: "billing.read"}); err != nil {
		t.Fatalf("create group allow grant: %v", err)
	}
	if err := s.CreateGrant(ctx, Grant{OwnerKind: PrincipalGroup, OwnerID: "g-1", Effect: EffectDeny, TeamScope: "*", PermissionName: "billing.read", ObjectScope: &obj}); err != nil {
		t.Fatalf("create group deny grant: %v", err)
	}
	if err := s.CreateGrant(ctx, Grant{OwnerKind: PrincipalRole, OwnerID: "r-1", Effect: EffectAllow, TeamScope: "*", PermissionName: "billing.read", ExpiresAt: &expired}); err != nil {
		t.Fatalf("create expired role grant: %v", err)
	}

	if _, err := s.GrantsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: ""}); err == nil {
		t.Fatalf("expected principal validation error")
	}
	principalGrants, err := s.GrantsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"})
	if err != nil {
		t.Fatalf("grants for principal: %v", err)
	}
	if len(principalGrants) != 1 {
		t.Fatalf("expected one active user grant, got %d", len(principalGrants))
	}
	principalGrants[0].TeamScope = "mutated"
	again, err := s.GrantsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: "u-1"})
	if err != nil {
		t.Fatalf("grants for principal second read: %v", err)
	}
	if again[0].TeamScope != "*" {
		t.Fatalf("expected grant copy on read")
	}

	if _, err := s.GrantsForOwners(ctx, []PrincipalRef{{Kind: PrincipalUser, ID: ""}}, Request{}); err == nil {
		t.Fatalf("expected owner validation error")
	}
	ownerGrants, err := s.GrantsForOwners(ctx,
		[]PrincipalRef{{Kind: PrincipalUser, ID: "u-1"}, {Kind: PrincipalGroup, ID: "g-1"}, {Kind: PrincipalRole, ID: "r-1"}},
		Request{Perm: "billing.read"},
	)
	if err != nil {
		t.Fatalf("grants for owners: %v", err)
	}
	if len(ownerGrants) != 3 {
		t.Fatalf("expected 3 active billing.read grants (expired skipped), got %d", len(ownerGrants))
	}

	if _, err := s.PrincipalsWithGrant(ctx, Request{}); err == nil {
		t.Fatalf("expected missing permission error")
	}
	hits, err := s.PrincipalsWithGrant(ctx, Request{Perm: "billing.read"})
	if err != nil {
		t.Fatalf("principals with grant: %v", err)
	}
	got := make([]string, 0, len(hits))
	for _, hit := range hits {
		got = append(got, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(got)
	want := []string{"user:u-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected deny-overrides-allow result %v, got %v", want, got)
	}
}

func TestBootstrapStore_ExpandRolesAndHelpers(t *testing.T) {
	ctx := context.Background()
	s := newBootstrapStore()

	expanded, err := s.ExpandRoles(ctx, []string{"  r-1  ", "r-1", "", "r-2"})
	if err != nil {
		t.Fatalf("expand roles: %v", err)
	}
	if !reflect.DeepEqual(expanded, []string{"r-1", "r-2"}) {
		t.Fatalf("unexpected expanded roles %v", expanded)
	}

	if principalKey(PrincipalRef{Kind: PrincipalUser, ID: "u-1"}) != "user:u-1" {
		t.Fatalf("unexpected principalKey format")
	}
	if !mapEquals(map[string]any{"a": 1}, map[string]any{"a": "1"}) {
		t.Fatalf("mapEquals should compare fmt.Sprint values")
	}
	if mapEquals(map[string]any{"a": 1}, map[string]any{"a": 2}) {
		t.Fatalf("mapEquals should detect different values")
	}

	obj := "record-1"
	expires := time.Now().UTC().Add(time.Hour)
	original := Grant{
		OwnerKind:        PrincipalUser,
		OwnerID:          "u-1",
		Effect:           EffectAllow,
		TeamScope:        "*",
		ObjectScope:      &obj,
		PermissionName:   "records.read",
		ExpiresAt:        &expires,
		RestrictedFields: []string{"secret"},
		VariableSpec:     map[string]any{"team": 42},
	}
	cloned := cloneGrant(original)
	cloned.RestrictedFields[0] = "mutated"
	cloned.VariableSpec["team"] = 7
	if original.RestrictedFields[0] != "secret" {
		t.Fatalf("cloneGrant should deep copy restricted fields")
	}
	if original.VariableSpec["team"] != 42 {
		t.Fatalf("cloneGrant should deep copy variable spec")
	}
}
