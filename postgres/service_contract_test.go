package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/testingharness"
)

type postgresHarnessStore struct {
	*Store
}

func newContractStore(t *testing.T) *postgresHarnessStore {
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

	return &postgresHarnessStore{Store: store}
}

func TestPostgresServiceContractSuite(t *testing.T) {
	h := testingharness.NewHarness(newContractStore(t))
	h.RunAll(t)
}

func (s *postgresHarnessStore) HarnessName() string {
	return "postgres"
}

func (s *postgresHarnessStore) Reset(ctx context.Context, t *testing.T) {
	t.Helper()

	stmt := `truncate table
		group_members,
		group_closure,
		role_inheritance,
		role_closure,
		principal_roles,
		permission_grants,
		users,
		groups,
		roles
	restart identity cascade`

	if _, err := s.pool.Exec(ctx, stmt); err != nil {
		t.Fatalf("reset postgres harness data: %v", err)
	}
}

func (s *postgresHarnessStore) SeedDenyOverridesAllow(ctx context.Context, t *testing.T) permissions.Request {
	seedDenyOverridesAllowScenario(t, ctx, s.pool)
	teamID := int64(42)
	return permissions.Request{UserID: "u-1", TeamID: &teamID, Object: "billing", Perm: "billing.read"}
}

func (s *postgresHarnessStore) SeedStrictBindingError(ctx context.Context, t *testing.T) permissions.Request {
	seedStrictBindingScenario(t, ctx, s.pool)
	teamID := int64(42)
	return permissions.Request{UserID: "u-1", TeamID: &teamID, Object: "billing", Perm: "billing.read"}
}

func (s *postgresHarnessStore) SeedEffectivePermissions(ctx context.Context, t *testing.T) testingharness.EffectiveExpectation {
	seedEffectivePermissionsScenario(t, ctx, s.pool)
	teamID := int64(7)
	return testingharness.EffectiveExpectation{
		UserID:          "u-1",
		TeamID:          &teamID,
		ExpectedPerms:   []string{"report.write"},
		UnexpectedPerms: []string{"report.read"},
	}
}

func seedDenyOverridesAllowScenario(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	stmts := []string{
		"insert into users (id, display_name) values ('u-1', 'User One')",
		"insert into groups (id, name) values ('g-1', 'Group One')",
		"insert into group_members (group_id, user_id) values ('g-1', 'u-1')",
		"insert into group_closure (ancestor_group_id, descendant_group_id, depth) values ('g-1', 'g-1', 0)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('user', 'u-1', 'allow', '42', null, 'billing.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('group', 'g-1', 'deny', '42', '*', 'billing.read', '{}'::jsonb)",
	}
	seedStatements(t, ctx, pool, stmts)
}

func seedStrictBindingScenario(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	stmts := []string{
		"insert into users (id, display_name) values ('u-1', 'User One')",
		"insert into roles (id, code) values ('r-parent', 'parent')",
		"insert into roles (id, code) values ('r-child', 'child')",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-parent', 'r-parent', 0)",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-parent', 'r-child', 1)",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-child', 'r-child', 0)",
		"insert into principal_roles (principal_kind, principal_id, role_id, binding_values) values ('user', 'u-1', 'r-parent', '{\"team\":42}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('role', 'r-child', 'allow', '*', null, 'billing.read', '{\"team\":\"required\"}'::jsonb)",
	}
	seedStatements(t, ctx, pool, stmts)
}

func seedEffectivePermissionsScenario(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	stmts := []string{
		"insert into users (id, display_name) values ('u-1', 'User One')",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('user', 'u-1', 'allow', '7', null, 'report.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('user', 'u-1', 'deny', '7', null, 'report.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('user', 'u-1', 'allow', '7', null, 'report.write', '{}'::jsonb)",
	}
	seedStatements(t, ctx, pool, stmts)
}

func seedStatements(t *testing.T, ctx context.Context, pool *pgxpool.Pool, stmts []string) {
	t.Helper()
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed statement failed (%s): %v", stmt, err)
		}
	}
}
