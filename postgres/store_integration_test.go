package postgres

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wtiger001/go-permissions"
)

func newTestStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()

	pgCfg := CreateDefaultPostgresqlContainer(t)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, pgCfg.ConnectionString())
	if err != nil {
		t.Fatalf("create pgx pool: %v", err)
	}
	t.Cleanup(pool.Close)

	store := NewStore(pool)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}

	return store, pool
}

func TestEnsureSchemaCreatesCoreTables(t *testing.T) {
	_, pool := newTestStore(t)
	ctx := context.Background()

	for _, table := range []string{
		"roles",
		"role_inheritance",
		"role_closure",
		"principal_roles",
		"permission_grants",
	} {
		var exists string
		if err := pool.QueryRow(ctx, "select to_regclass('public.' || $1)", table).Scan(&exists); err != nil {
			t.Fatalf("lookup table %s: %v", table, err)
		}
		if exists == "" {
			t.Fatalf("expected table %s to exist", table)
		}
	}
}

func TestStoreQueries_EndToEnd(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	seedStatements := []string{
		"insert into roles (id, code) values ('r-base', 'base')",
		"insert into roles (id, code) values ('r-child', 'child')",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-base', 'r-base', 0)",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-base', 'r-child', 1)",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-child', 'r-child', 0)",
		"insert into principal_roles (principal_kind, principal_id, role_id, binding_values) values ('user', 'u-1', 'r-base', '{\"team\":42}')",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('user', 'u-1', 'allow', '42', null, 'billing.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('group', 'g-parent', 'allow', '42', '*', 'billing.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('role', 'r-child', 'deny', '42', 'billing', 'billing.read', '{}'::jsonb)",
	}

	for _, stmt := range seedStatements {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed statement failed (%s): %v", stmt, err)
		}
	}

	// Group IDs are resolved externally by the identity provider; pass them directly.
	groupIDs := []string{"g-child", "g-parent"}

	roleAssignments, err := store.ListRoleAssignmentsForUserAndGroups(ctx, "u-1", groupIDs)
	if err != nil {
		t.Fatalf("ListRoleAssignmentsForUserAndGroups: %v", err)
	}
	if len(roleAssignments) != 1 {
		t.Fatalf("expected 1 role assignment, got %d", len(roleAssignments))
	}
	if roleAssignments[0].RoleID != "r-base" {
		t.Fatalf("expected role assignment r-base, got %s", roleAssignments[0].RoleID)
	}

	expandedRoleIDs, err := store.ListExpandedRoleIDs(ctx, []string{"r-base"})
	if err != nil {
		t.Fatalf("ListExpandedRoleIDs: %v", err)
	}
	if len(expandedRoleIDs) != 2 {
		t.Fatalf("expected 2 expanded roles, got %d (%v)", len(expandedRoleIDs), expandedRoleIDs)
	}

	teamID := int64(42)
	owners := []permissions.PrincipalRef{
		{Kind: permissions.PrincipalUser, ID: "u-1"},
		{Kind: permissions.PrincipalGroup, ID: "g-parent"},
		{Kind: permissions.PrincipalRole, ID: "r-child"},
	}

	grants, err := store.ListGrantsForOwners(ctx, owners, permissions.Request{
		UserID: "u-1",
		TeamID: &teamID,
		Object: "billing",
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("ListGrantsForOwners: %v", err)
	}
	if len(grants) != 3 {
		t.Fatalf("expected 3 matching grants, got %d", len(grants))
	}
}

func TestListPrincipalsWithGrant_DenyOverridesAllow(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	seedStatements := []string{
		"insert into roles (id, code) values ('r-1', 'Role One')",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('user', 'u-1', 'allow', '42', null, 'billing.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('group', 'g-1', 'allow', '42', null, 'billing.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('group', 'g-1', 'deny', '42', '*', 'billing.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('role', 'r-1', 'allow', '*', null, 'billing.read', '{}'::jsonb)",
	}

	for _, stmt := range seedStatements {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed statement failed (%s): %v", stmt, err)
		}
	}

	teamID := int64(42)
	hits, err := store.ListPrincipalsWithGrant(ctx, permissions.Request{TeamID: &teamID, Object: "billing", Perm: "billing.read"})
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

func TestCreateGrants_BulkInsert(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	grants := []permissions.Grant{
		{
			OwnerKind:      permissions.PrincipalUser,
			OwnerID:        "u-1",
			Effect:         permissions.EffectAllow,
			TeamScope:      "*",
			PermissionName: "announcements.read",
		},
		{
			OwnerKind:      permissions.PrincipalUser,
			OwnerID:        "u-2",
			Effect:         permissions.EffectAllow,
			TeamScope:      "*",
			PermissionName: "announcements.read",
		},
	}

	if err := store.CreateGrants(ctx, grants); err != nil {
		t.Fatalf("CreateGrants: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, "select count(*) from permission_grants where permission_name = 'announcements.read'").Scan(&count); err != nil {
		t.Fatalf("count permission grants: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 inserted grants, got %d", count)
	}
}
