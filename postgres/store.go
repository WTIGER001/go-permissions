package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wtiger001/go-permissions"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) ListKnownGroupIDs(ctx context.Context) ([]string, error) {
	const query = `
select group_id
from (
	select distinct principal_id as group_id
	from principal_roles
	where principal_kind = 'group'

	union

	select distinct owner_id as group_id
	from permission_grants
	where owner_kind = 'group'
) g
`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query known groups: %w", err)
	}
	defer rows.Close()

	groupIDs := make([]string, 0, 16)
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err != nil {
			return nil, fmt.Errorf("scan known group ID: %w", err)
		}
		groupIDs = append(groupIDs, groupID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate known groups: %w", err)
	}

	return groupIDs, nil
}

func (s *Store) IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error) {
	const query = `
select exists (
	select 1
	from group_members gm
	join group_closure gc on gc.descendant_group_id = gm.group_id
	where gm.user_id = $1
	  and gc.ancestor_group_id = $2
)
`

	var exists bool
	if err := s.pool.QueryRow(ctx, query, userID, groupID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check user group membership: %w", err)
	}

	return exists, nil
}

func (s *Store) EnsureSchema(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin schema transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	stmts := []string{
		`do $$ begin
			create type principal_type as enum ('user', 'group', 'role');
		exception
			when duplicate_object then null;
		end $$;`,
		`do $$ begin
			create type grant_effect as enum ('allow', 'deny');
		exception
			when duplicate_object then null;
		end $$;`,
		`create table if not exists users (
			id text primary key,
			external_key text unique,
			email text unique,
			display_name text not null,
			created_at timestamptz not null default now(),
			updated_at timestamptz not null default now()
		);`,
		`create table if not exists groups (
			id text primary key,
			team_id bigint null,
			name text not null,
			created_at timestamptz not null default now(),
			updated_at timestamptz not null default now(),
			unique (team_id, name)
		);`,
		`create table if not exists roles (
			id text primary key,
			code text not null unique,
			description text,
			built_in boolean not null default false,
			created_at timestamptz not null default now(),
			updated_at timestamptz not null default now()
		);`,
		`create table if not exists group_members (
			group_id text not null references groups(id) on delete cascade,
			user_id text not null references users(id) on delete cascade,
			created_at timestamptz not null default now(),
			primary key (group_id, user_id)
		);`,
		`create table if not exists group_closure (
			ancestor_group_id text not null references groups(id) on delete cascade,
			descendant_group_id text not null references groups(id) on delete cascade,
			depth int not null,
			primary key (ancestor_group_id, descendant_group_id)
		);`,
		`create table if not exists role_inheritance (
			parent_role_id text not null references roles(id) on delete cascade,
			child_role_id text not null references roles(id) on delete cascade,
			primary key (parent_role_id, child_role_id)
		);`,
		`create table if not exists role_closure (
			ancestor_role_id text not null references roles(id) on delete cascade,
			descendant_role_id text not null references roles(id) on delete cascade,
			depth int not null,
			primary key (ancestor_role_id, descendant_role_id)
		);`,
		`create table if not exists principal_roles (
			id bigserial primary key,
			principal_kind principal_type not null,
			principal_id text not null,
			role_id text not null references roles(id) on delete cascade,
			binding_values jsonb not null default '{}'::jsonb,
			created_at timestamptz not null default now(),
			unique (principal_kind, principal_id, role_id, binding_values)
		);`,
		`create table if not exists permission_grants (
			id bigserial primary key,
			owner_kind principal_type not null,
			owner_id text not null,
			effect grant_effect not null default 'allow',
			team_scope text not null,
			object_scope text null,
			permission_name text not null,
			field_allowlist text[] null,
			variable_spec jsonb not null default '{}'::jsonb,
			created_at timestamptz not null default now(),
			updated_at timestamptz not null default now()
		);`,
		`create index if not exists idx_group_members_user on group_members (user_id, group_id);`,
		`create index if not exists idx_group_closure_descendant on group_closure (descendant_group_id, ancestor_group_id);`,
		`create index if not exists idx_role_assignments_principal on principal_roles (principal_kind, principal_id, role_id);`,
		`create index if not exists idx_role_closure_ancestor on role_closure (ancestor_role_id, descendant_role_id);`,
		`create index if not exists idx_permission_grants_owner_perm on permission_grants (owner_kind, owner_id, permission_name);`,
		`create index if not exists idx_permission_grants_match on permission_grants (team_scope, object_scope, permission_name, effect);`,
	}

	for _, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("ensure schema statement failed: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema transaction: %w", err)
	}

	return nil
}

func (s *Store) ListUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	const query = `
select gc.ancestor_group_id
from group_members gm
join group_closure gc on gc.descendant_group_id = gm.group_id
where gm.user_id = $1
`

	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query user groups: %w", err)
	}
	defer rows.Close()

	groupIDs := make([]string, 0, 8)
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err != nil {
			return nil, fmt.Errorf("scan group ID: %w", err)
		}
		groupIDs = append(groupIDs, groupID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user groups: %w", err)
	}

	return groupIDs, nil
}

func (s *Store) ListRoleAssignmentsForUserAndGroups(ctx context.Context, userID string, groupIDs []string) ([]permissions.RoleAssignment, error) {
	const query = `
select distinct pr.role_id, pr.binding_values
from principal_roles pr
where (pr.principal_kind = 'user' and pr.principal_id = $1)
	or (pr.principal_kind = 'group' and pr.principal_id = any($2::text[]))
`

	rows, err := s.pool.Query(ctx, query, userID, groupIDs)
	if err != nil {
		return nil, fmt.Errorf("query role assignments: %w", err)
	}
	defer rows.Close()

	assignments := make([]permissions.RoleAssignment, 0, 8)
	for rows.Next() {
		var roleID string
		var bindingRaw []byte
		if err := rows.Scan(&roleID, &bindingRaw); err != nil {
			return nil, fmt.Errorf("scan role assignment: %w", err)
		}

		bindingValues := map[string]any{}
		if len(bindingRaw) > 0 {
			if err := json.Unmarshal(bindingRaw, &bindingValues); err != nil {
				return nil, fmt.Errorf("unmarshal binding values: %w", err)
			}
		}

		assignments = append(assignments, permissions.RoleAssignment{
			RoleID:        roleID,
			BindingValues: bindingValues,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role assignments: %w", err)
	}

	return assignments, nil
}

func (s *Store) ListExpandedRoleIDs(ctx context.Context, roleIDs []string) ([]string, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}

	const query = `
select distinct rc.descendant_role_id
from role_closure rc
where rc.ancestor_role_id = any($1::text[])
`

	rows, err := s.pool.Query(ctx, query, roleIDs)
	if err != nil {
		return nil, fmt.Errorf("query expanded roles: %w", err)
	}
	defer rows.Close()

	expandedRoleIDs := make([]string, 0, len(roleIDs))
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			return nil, fmt.Errorf("scan expanded role ID: %w", err)
		}
		expandedRoleIDs = append(expandedRoleIDs, roleID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expanded roles: %w", err)
	}

	return expandedRoleIDs, nil
}

func (s *Store) ListGrantsForOwners(ctx context.Context, owners []permissions.PrincipalRef, req permissions.Request) ([]permissions.Grant, error) {
	if len(owners) == 0 {
		return nil, nil
	}

	kinds := make([]string, 0, len(owners))
	ids := make([]string, 0, len(owners))
	for _, owner := range owners {
		if err := owner.Validate(); err != nil {
			return nil, err
		}
		kinds = append(kinds, string(owner.Kind))
		ids = append(ids, owner.ID)
	}

	var teamScope *string
	if req.TeamID != nil {
		value := fmt.Sprintf("%d", *req.TeamID)
		teamScope = &value
	}

	const query = `
with owner_refs as (
	select owner_kind, owner_id
	from unnest($1::principal_type[], $2::text[]) as t(owner_kind, owner_id)
)
select
	pg.id,
	pg.owner_kind,
	pg.owner_id,
	pg.effect,
	pg.team_scope,
	pg.object_scope,
	pg.permission_name,
	pg.field_allowlist,
	pg.variable_spec
from permission_grants pg
join owner_refs r on r.owner_kind = pg.owner_kind and r.owner_id = pg.owner_id
where ($3::text = '' or pg.permission_name = $3)
	and (
		($4::text is null and pg.team_scope = '*')
		or
		($4::text is not null and (pg.team_scope = '*' or pg.team_scope = $4::text))
	)
	and (pg.object_scope is null or pg.object_scope = '*' or pg.object_scope = $5::text)
`

	rows, err := s.pool.Query(ctx, query, kinds, ids, req.Perm, teamScope, req.Object)
	if err != nil {
		return nil, fmt.Errorf("query grants: %w", err)
	}
	defer rows.Close()

	grants := make([]permissions.Grant, 0, 16)
	for rows.Next() {
		var grant permissions.Grant
		var ownerKind string
		var effect string
		var variableSpecRaw []byte

		if err := rows.Scan(
			&grant.ID,
			&ownerKind,
			&grant.OwnerID,
			&effect,
			&grant.TeamScope,
			&grant.ObjectScope,
			&grant.PermissionName,
			&grant.FieldAllowlist,
			&variableSpecRaw,
		); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}

		grant.OwnerKind = permissions.PrincipalKind(ownerKind)
		grant.Effect = permissions.Effect(effect)

		variableSpec := map[string]any{}
		if len(variableSpecRaw) > 0 {
			if err := json.Unmarshal(variableSpecRaw, &variableSpec); err != nil {
				return nil, fmt.Errorf("unmarshal variable spec: %w", err)
			}
		}
		grant.VariableSpec = variableSpec

		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate grants: %w", err)
	}

	return grants, nil
}

func (s *Store) ListPrincipalsWithGrant(ctx context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	if req.Perm == "" {
		return nil, fmt.Errorf("permission name is required")
	}

	var teamScope *string
	if req.TeamID != nil {
		value := fmt.Sprintf("%d", *req.TeamID)
		teamScope = &value
	}

	const query = `
select distinct
	pg.owner_kind,
	pg.owner_id,
	pg.team_scope,
	pg.object_scope,
	pg.permission_name
from permission_grants pg
where pg.effect = 'allow'
	and pg.permission_name = $1
	and (
		($2::text is null and pg.team_scope = '*')
		or
		($2::text is not null and (pg.team_scope = '*' or pg.team_scope = $2::text))
	)
	and (pg.object_scope is null or pg.object_scope = '*' or pg.object_scope = $3::text)
	and not exists (
		select 1
		from permission_grants pd
		where pd.owner_kind = pg.owner_kind
			and pd.owner_id = pg.owner_id
			and pd.effect = 'deny'
			and pd.permission_name = $1
			and (
				($2::text is null and pd.team_scope = '*')
				or
				($2::text is not null and (pd.team_scope = '*' or pd.team_scope = $2::text))
			)
			and (pd.object_scope is null or pd.object_scope = '*' or pd.object_scope = $3::text)
	)
`

	rows, err := s.pool.Query(ctx, query, req.Perm, teamScope, req.Object)
	if err != nil {
		return nil, fmt.Errorf("query principals with grant: %w", err)
	}
	defer rows.Close()

	hits := make([]permissions.PrincipalHit, 0, 16)
	for rows.Next() {
		var hit permissions.PrincipalHit
		var ownerKind string
		if err := rows.Scan(&ownerKind, &hit.ID, &hit.TeamScope, &hit.ObjectScope, &hit.PermissionName); err != nil {
			return nil, fmt.Errorf("scan principal hit: %w", err)
		}
		hit.Kind = permissions.PrincipalKind(ownerKind)
		hits = append(hits, hit)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principals with grant: %w", err)
	}

	return hits, nil
}

func (s *Store) CreateGrant(ctx context.Context, grant permissions.Grant) error {
	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		return fmt.Errorf("team scope is required")
	}

	variableSpec := map[string]any{}
	for k, v := range grant.VariableSpec {
		variableSpec[k] = v
	}

	variableSpecRaw, err := json.Marshal(variableSpec)
	if err != nil {
		return fmt.Errorf("marshal variable spec: %w", err)
	}

	const stmt = `
insert into permission_grants (
	owner_kind,
	owner_id,
	effect,
	team_scope,
	object_scope,
	permission_name,
	field_allowlist,
	variable_spec
) values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
`

	if _, err := s.pool.Exec(
		ctx,
		stmt,
		string(grant.OwnerKind),
		grant.OwnerID,
		string(grant.Effect),
		grant.TeamScope,
		grant.ObjectScope,
		grant.PermissionName,
		grant.FieldAllowlist,
		variableSpecRaw,
	); err != nil {
		return fmt.Errorf("insert permission grant: %w", err)
	}

	return nil
}

func (s *Store) AssignRole(ctx context.Context, principal permissions.PrincipalRef, roleID string, bindingValues map[string]any) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if principal.Kind != permissions.PrincipalUser && principal.Kind != permissions.PrincipalGroup {
		return fmt.Errorf("role assignments support only user or group principals")
	}
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	bindingCopy := map[string]any{}
	for k, v := range bindingValues {
		bindingCopy[k] = v
	}
	bindingRaw, err := json.Marshal(bindingCopy)
	if err != nil {
		return fmt.Errorf("marshal role binding values: %w", err)
	}

	const stmt = `
insert into principal_roles (
	principal_kind,
	principal_id,
	role_id,
	binding_values
) values ($1, $2, $3, $4::jsonb)
`

	if _, err := s.pool.Exec(ctx, stmt, string(principal.Kind), principal.ID, roleID, bindingRaw); err != nil {
		return fmt.Errorf("insert principal role assignment: %w", err)
	}

	return nil
}
