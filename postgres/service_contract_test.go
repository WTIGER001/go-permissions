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
	if err := ensureIdentityTables(ctx, pool); err != nil {
		t.Fatalf("ensure identity tables: %v", err)
	}

	return &postgresHarnessStore{Store: store}
}

// ensureIdentityTables creates user/group/team tables needed by the harness identity provider.
// These are test-only and not managed by the production EnsureSchema.
func ensureIdentityTables(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`create table if not exists users (
			id text primary key,
			display_name text not null
		);`,
		`create table if not exists groups (
			id text primary key,
			name text not null
		);`,
		`create table if not exists group_members (
			group_id text not null references groups(id) on delete cascade,
			user_id text not null references users(id) on delete cascade,
			primary key (group_id, user_id)
		);`,
		`create table if not exists group_closure (
			ancestor_group_id text not null references groups(id) on delete cascade,
			descendant_group_id text not null references groups(id) on delete cascade,
			depth int not null,
			primary key (ancestor_group_id, descendant_group_id)
		);`,
		`create table if not exists teams (
			id text primary key,
			name text not null
		);`,
		`create table if not exists team_members (
			team_id text not null references teams(id) on delete cascade,
			principal_kind text not null check (principal_kind in ('user','group')),
			principal_id text not null,
			primary key (team_id, principal_kind, principal_id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
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
		team_members,
		teams,
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

func (s *postgresHarnessStore) GetUserGroups(ctx context.Context, userID string) ([]string, error) {
	const query = `
select gc.ancestor_group_id
from group_members gm
join group_closure gc on gc.descendant_group_id = gm.group_id
where gm.user_id = $1
`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *postgresHarnessStore) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	const query = `
select distinct gm.user_id
from group_members gm
join group_closure gc on gc.descendant_group_id = gm.group_id
where gc.ancestor_group_id = $1
`
	rows, err := s.pool.Query(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *postgresHarnessStore) GetUserTeams(ctx context.Context, userID string) ([]string, error) {
	const query = `
select distinct tm.team_id
from team_members tm
where (tm.principal_kind = 'user' and tm.principal_id = $1)
   or (tm.principal_kind = 'group' and tm.principal_id in (
        select gc.ancestor_group_id
        from group_members gm
	join group_closure gc on gc.descendant_group_id = gm.group_id
        where gm.user_id = $1
   ))
`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *postgresHarnessStore) IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error) {
	const query = `
select exists (
	select 1 from group_members gm
	join group_closure gc on gc.descendant_group_id = gm.group_id
	where gm.user_id = $1 and gc.ancestor_group_id = $2
)
`
	var exists bool
	err := s.pool.QueryRow(ctx, query, userID, groupID).Scan(&exists)
	return exists, err
}

func (s *postgresHarnessStore) IsUserInTeam(ctx context.Context, userID, teamID string) (bool, error) {
	const query = `
select exists (
	select 1
	from team_members tm
	where tm.team_id = $2
	  and (
	    (tm.principal_kind = 'user' and tm.principal_id = $1)
	    or (
	      tm.principal_kind = 'group'
	      and tm.principal_id in (
	        select gc.ancestor_group_id
	        from group_members gm
	        join group_closure gc on gc.descendant_group_id = gm.group_id
	        where gm.user_id = $1
	      )
	    )
	  )
)
`
	var exists bool
	err := s.pool.QueryRow(ctx, query, userID, teamID).Scan(&exists)
	return exists, err
}

func (s *postgresHarnessStore) SeedDenyOverridesAllow(ctx context.Context, t *testing.T) permissions.Request {
	seedDenyOverridesAllowScenario(t, ctx, s.pool)
	teamID := "42"
	return permissions.Request{UserID: "u-1", TeamID: teamID, Object: "billing", Perm: "billing.read"}
}

func (s *postgresHarnessStore) SeedStrictBindingError(ctx context.Context, t *testing.T) permissions.Request {
	seedStrictBindingScenario(t, ctx, s.pool)
	teamID := "42"
	return permissions.Request{UserID: "u-1", TeamID: teamID, Object: "billing", Perm: "billing.read"}
}

func (s *postgresHarnessStore) SeedEffectivePermissions(ctx context.Context, t *testing.T) testingharness.EffectiveExpectation {
	seedEffectivePermissionsScenario(t, ctx, s.pool)
	teamID := "7"
	return testingharness.EffectiveExpectation{
		UserID:          "u-1",
		TeamID:          teamID,
		ExpectedPerms:   []string{"report.write"},
		UnexpectedPerms: []string{"report.read"},
	}
}

func (s *postgresHarnessStore) SeedTransitiveRoles(ctx context.Context, t *testing.T) permissions.Request {
	t.Helper()
	// Create three roles and build a 3-hop chain via AddRoleInheritance.
	// Grant is only on r-leaf; the service must expand transitively to find it.
	stmts := []string{
		"insert into users (id, display_name) values ('u-1', 'User One')",
		"insert into roles (id, code) values ('r-top', 'top')",
		"insert into roles (id, code) values ('r-mid', 'mid')",
		"insert into roles (id, code) values ('r-leaf', 'leaf')",
		// Seed self-closure rows so that AddRoleInheritance can find ancestors.
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-top', 'r-top', 0)",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-mid', 'r-mid', 0)",
		"insert into role_closure (ancestor_role_id, descendant_role_id, depth) values ('r-leaf', 'r-leaf', 0)",
		"insert into principal_roles (principal_kind, principal_id, role_id, binding_values) values ('user', 'u-1', 'r-top', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('role', 'r-leaf', 'allow', '*', null, 'reports.view', '{}'::jsonb)",
	}
	seedStatements(t, ctx, s.pool, stmts)

	if err := s.AddRoleInheritance(ctx, "r-top", "r-mid"); err != nil {
		t.Fatalf("AddRoleInheritance r-top->r-mid: %v", err)
	}
	if err := s.AddRoleInheritance(ctx, "r-mid", "r-leaf"); err != nil {
		t.Fatalf("AddRoleInheritance r-mid->r-leaf: %v", err)
	}

	return permissions.Request{UserID: "u-1", TeamID: "", Object: "reports", Perm: "reports.view"}
}

func seedDenyOverridesAllowScenario(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	stmts := []string{
		"insert into users (id, display_name) values ('u-1', 'User One')",
		"insert into groups (id, name) values ('g-1', 'Group One')",
		"insert into group_members (group_id, user_id) values ('g-1', 'u-1')",
		"insert into group_closure (ancestor_group_id, descendant_group_id, depth) values ('g-1', 'g-1', 0)",
		"insert into teams (id, name) values ('42', 'Billing Team')",
		"insert into team_members (team_id, principal_kind, principal_id) values ('42', 'user', 'u-1')",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('user', 'u-1', 'allow', '42', null, 'billing.read', '{}'::jsonb)",
		"insert into permission_grants (owner_kind, owner_id, effect, team_scope, object_scope, permission_name, variable_spec) values ('group', 'g-1', 'deny', '42', '*', 'billing.read', '{}'::jsonb)",
	}
	seedStatements(t, ctx, pool, stmts)
}

func seedStrictBindingScenario(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	stmts := []string{
		"insert into users (id, display_name) values ('u-1', 'User One')",
		"insert into teams (id, name) values ('42', 'Billing Team')",
		"insert into team_members (team_id, principal_kind, principal_id) values ('42', 'user', 'u-1')",
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
		"insert into teams (id, name) values ('7', 'Reporting Team')",
		"insert into team_members (team_id, principal_kind, principal_id) values ('7', 'user', 'u-1')",
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
