package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wtiger001/go-permissions"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ permissions.PermissionStore = (*Store)(nil)
var _ permissions.BulkGrantStore = (*Store)(nil)

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
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
		`create table if not exists roles (
			id text primary key,
			code text not null unique,
			description text,
			built_in boolean not null default false,
			is_disabled boolean not null default false,
			created_at timestamptz not null default now(),
			updated_at timestamptz not null default now()
		);`,
		`alter table roles add column if not exists built_in boolean not null default false;`,
		`alter table roles add column if not exists is_disabled boolean not null default false;`,
		`alter table roles add column if not exists scope text not null default '';`,
		`alter table roles add column if not exists tags text[] not null default '{}';`,
		`create table if not exists role_inheritance (
			parent_role_id text not null,
			child_role_id text not null,
			primary key (parent_role_id, child_role_id)
		);`,
		`create table if not exists role_closure (
			ancestor_role_id text not null,
			descendant_role_id text not null,
			depth int not null,
			primary key (ancestor_role_id, descendant_role_id)
		);`,
		`create table if not exists principal_roles (
			id bigserial primary key,
			principal_kind principal_type not null,
			principal_id text not null,
			role_id text not null,
			binding_values jsonb not null default '{}'::jsonb,
			created_at timestamptz not null default now(),
			unique (principal_kind, principal_id, role_id, binding_values)
		);`,
		`create table if not exists disabled_builtin_roles (
			role_id text primary key,
			disabled_at timestamptz not null default now()
		);`,
		`create table if not exists permission_grants (
			id bigserial primary key,
			owner_kind principal_type not null,
			owner_id text not null,
			effect grant_effect not null default 'allow',
			team_scope text not null,
			object_scope text null,
			permission_name text not null,
			expires_at timestamptz null,
			field_allowlist text[] null,
			variable_spec jsonb not null default '{}'::jsonb,
			created_at timestamptz not null default now(),
			updated_at timestamptz not null default now()
		);`,
		`alter table permission_grants add column if not exists expires_at timestamptz null;`,
		`create index if not exists idx_role_assignments_principal on principal_roles (principal_kind, principal_id, role_id);`,
		`create index if not exists idx_role_closure_ancestor on role_closure (ancestor_role_id, descendant_role_id);`,
		`create index if not exists idx_permission_grants_owner_perm on permission_grants (owner_kind, owner_id, permission_name);`,
		`create index if not exists idx_permission_grants_match on permission_grants (team_scope, object_scope, permission_name, effect);`,
		`create index if not exists idx_permission_grants_object on permission_grants (object_scope);`,
		`create index if not exists idx_permission_grants_perm_pattern on permission_grants (permission_name text_pattern_ops);`,
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

func (s *Store) RoleAssignmentsForPrincipal(ctx context.Context, principal permissions.PrincipalRef) ([]permissions.RoleAssignment, error) {
	if err := principal.Validate(); err != nil {
		return nil, err
	}

	const query = `
select pr.role_id, pr.binding_values
from principal_roles pr
where pr.principal_kind = $1 and pr.principal_id = $2
`

	rows, err := s.pool.Query(ctx, query, string(principal.Kind), principal.ID)
	if err != nil {
		return nil, fmt.Errorf("query role assignments for principal: %w", err)
	}
	defer rows.Close()

	assignments := make([]permissions.RoleAssignment, 0, 8)
	for rows.Next() {
		var roleID string
		var bindingRaw []byte
		if err := rows.Scan(&roleID, &bindingRaw); err != nil {
			return nil, fmt.Errorf("scan role assignment for principal: %w", err)
		}

		bindingValues := map[string]any{}
		if len(bindingRaw) > 0 {
			if err := json.Unmarshal(bindingRaw, &bindingValues); err != nil {
				return nil, fmt.Errorf("unmarshal binding values for principal assignment: %w", err)
			}
		}

		assignments = append(assignments, permissions.RoleAssignment{RoleID: roleID, BindingValues: bindingValues})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role assignments for principal: %w", err)
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

func (s *Store) ExpandRoles(ctx context.Context, roleIDs []string) ([]string, error) {
	return s.ListExpandedRoleIDs(ctx, roleIDs)
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
	if req.TeamID != "" {
		value := req.TeamID
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
	pg.expires_at,
	pg.field_allowlist,
	pg.variable_spec
from permission_grants pg
join owner_refs r on r.owner_kind = pg.owner_kind and r.owner_id = pg.owner_id
where ($3::text = '' or pg.permission_name = $3)
	and (pg.expires_at is null or pg.expires_at > now())
	and (
		pg.team_scope = '*'
		or pg.team_scope like '?%'
		or ($4::text is not null and pg.team_scope = $4::text)
	)
	and (
		pg.object_scope is null
		or pg.object_scope = '*'
		or pg.object_scope like '?%'
		or ($5::text is not null and pg.object_scope = $5::text)
	)
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
			&grant.ExpiresAt,
			&grant.RestrictedFields,
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

func (s *Store) GrantsForOwners(ctx context.Context, owners []permissions.PrincipalRef, req permissions.Request) ([]permissions.Grant, error) {
	return s.ListGrantsForOwners(ctx, owners, req)
}

func (s *Store) GrantsForPrincipal(ctx context.Context, principal permissions.PrincipalRef) ([]permissions.Grant, error) {
	return s.ListGrantsForOwners(ctx, []permissions.PrincipalRef{principal}, permissions.Request{})
}

func (s *Store) ListPrincipalsWithGrant(ctx context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	if req.Perm == "" {
		return nil, fmt.Errorf("permission name is required")
	}

	var teamScope *string
	if req.TeamID != "" {
		value := req.TeamID
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
	and (pg.expires_at is null or pg.expires_at > now())
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
			and (pd.expires_at is null or pd.expires_at > now())
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

func (s *Store) PrincipalsWithGrant(ctx context.Context, req permissions.Request) ([]permissions.PrincipalHit, error) {
	return s.ListPrincipalsWithGrant(ctx, req)
}

func (s *Store) RoleDefinitions(ctx context.Context) ([]permissions.Role, error) {
	const query = `
select id, code, coalesce(description, ''), built_in, is_disabled, coalesce(scope, ''), coalesce(tags, '{}')
from roles
order by id
`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query role definitions: %w", err)
	}
	defer rows.Close()

	roles := make([]permissions.Role, 0, 16)
	for rows.Next() {
		var role permissions.Role
		var scope string
		var tags []string
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.BuiltIn, &role.IsDisabled, &scope, &tags); err != nil {
			return nil, fmt.Errorf("scan role definition: %w", err)
		}
		role.Scope = permissions.RoleScope(scope)
		if tags == nil {
			tags = []string{}
		}
		role.Tags = tags
		role.VariableSpec = map[string]any{}
		role.Permissions = []string{}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role definitions: %w", err)
	}

	return roles, nil
}

func (s *Store) RoleDefinition(ctx context.Context, roleID string) (permissions.Role, error) {
	if roleID == "" {
		return permissions.Role{}, fmt.Errorf("role ID is required")
	}

	const query = `
select id, code, coalesce(description, ''), built_in, is_disabled, coalesce(scope, ''), coalesce(tags, '{}')
from roles
where id = $1
`

	var role permissions.Role
	var scope string
	var tags []string
	if err := s.pool.QueryRow(ctx, query, roleID).Scan(&role.ID, &role.Name, &role.Description, &role.BuiltIn, &role.IsDisabled, &scope, &tags); err != nil {
		return permissions.Role{}, fmt.Errorf("query role definition: %w", err)
	}

	role.Scope = permissions.RoleScope(scope)
	if tags == nil {
		tags = []string{}
	}
	role.Tags = tags
	role.VariableSpec = map[string]any{}
	role.Permissions = []string{}
	return role, nil
}

func (s *Store) CreateRole(ctx context.Context, role permissions.Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	tags := role.Tags
	if tags == nil {
		tags = []string{}
	}

	const insertRole = `
insert into roles (id, code, description, built_in, is_disabled, scope, tags)
values ($1, $2, $3, $4, $5, $6, $7)
`
	if _, err := tx.Exec(ctx, insertRole, role.ID, role.Name, role.Description, role.BuiltIn, role.IsDisabled, string(role.Scope), tags); err != nil {
		return fmt.Errorf("insert role: %w", err)
	}

	// Every role is its own ancestor at depth 0 so ExpandRoles works immediately.
	const insertSelfClosure = `
insert into role_closure (ancestor_role_id, descendant_role_id, depth)
values ($1, $1, 0)
on conflict do nothing
`
	if _, err := tx.Exec(ctx, insertSelfClosure, role.ID); err != nil {
		return fmt.Errorf("insert role self-closure: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit create role: %w", err)
	}

	return nil
}

func (s *Store) UpdateRole(ctx context.Context, role permissions.Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	tags := role.Tags
	if tags == nil {
		tags = []string{}
	}

	const stmt = `
update roles
set code = $2, description = $3, built_in = $4, is_disabled = $5, scope = $6, tags = $7, updated_at = now()
where id = $1
`
	tag, err := s.pool.Exec(ctx, stmt, role.ID, role.Name, role.Description, role.BuiltIn, role.IsDisabled, string(role.Scope), tags)
	if err != nil {
		return fmt.Errorf("update role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role not found: %s", role.ID)
	}

	return nil
}

func (s *Store) DeleteRole(ctx context.Context, roleID string) error {
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	const stmt = `delete from roles where id = $1`
	tag, err := s.pool.Exec(ctx, stmt, roleID)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role not found: %s", roleID)
	}

	return nil
}

// AddRoleInheritance inserts a parent→child direct edge into role_inheritance
// and extends role_closure so that every ancestor of the parent also sees all
// descendants of the child. The closure extension follows the standard
// closure-table algorithm: for every (ancestor, parent) row we add
// (ancestor, descendant) rows for all (child, descendant) rows.
func (s *Store) AddRoleInheritance(ctx context.Context, parentRoleID, childRoleID string) error {
	if parentRoleID == "" {
		return fmt.Errorf("parent role ID is required")
	}
	if childRoleID == "" {
		return fmt.Errorf("child role ID is required")
	}
	if parentRoleID == childRoleID {
		return fmt.Errorf("a role cannot inherit itself")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin role inheritance transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Insert the direct edge (idempotent).
	const insertEdge = `
insert into role_inheritance (parent_role_id, child_role_id)
values ($1, $2)
on conflict do nothing
`
	if _, err := tx.Exec(ctx, insertEdge, parentRoleID, childRoleID); err != nil {
		return fmt.Errorf("insert role inheritance edge: %w", err)
	}

	// Extend role_closure:
	// For each ancestor A of parentRoleID (including itself) and each
	// descendant D of childRoleID (including itself), insert (A, D).
	const extendClosure = `
insert into role_closure (ancestor_role_id, descendant_role_id, depth)
select a.ancestor_role_id, d.descendant_role_id,
       a.depth + d.depth + 1
from role_closure a
cross join role_closure d
where a.descendant_role_id = $1
  and d.ancestor_role_id   = $2
on conflict do nothing
`
	if _, err := tx.Exec(ctx, extendClosure, parentRoleID, childRoleID); err != nil {
		return fmt.Errorf("extend role closure: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit role inheritance transaction: %w", err)
	}

	return nil
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
	expires_at,
	field_allowlist,
	variable_spec
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
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
		grant.ExpiresAt,
		grant.RestrictedFields,
		variableSpecRaw,
	); err != nil {
		return fmt.Errorf("insert permission grant: %w", err)
	}

	return nil
}

func (s *Store) CreateGrants(ctx context.Context, grants []permissions.Grant) error {
	if len(grants) == 0 {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin grant transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	const stmt = `
insert into permission_grants (
	owner_kind,
	owner_id,
	effect,
	team_scope,
	object_scope,
	permission_name,
	expires_at,
	field_allowlist,
	variable_spec
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
`

	batch := &pgx.Batch{}
	for _, grant := range grants {
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

		batch.Queue(
			stmt,
			string(grant.OwnerKind),
			grant.OwnerID,
			string(grant.Effect),
			grant.TeamScope,
			grant.ObjectScope,
			grant.PermissionName,
			grant.ExpiresAt,
			grant.RestrictedFields,
			variableSpecRaw,
		)
	}

	results := tx.SendBatch(ctx, batch)
	for i := 0; i < len(grants); i++ {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return fmt.Errorf("insert permission grants: %w", err)
		}
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("close permission grant batch: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit grant transaction: %w", err)
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

func (s *Store) UnassignRole(
	ctx context.Context,
	principal permissions.PrincipalRef,
	roleID string,
	bindingValues map[string]any,
) error {

	if err := principal.Validate(); err != nil {
		return err
	}
	if principal.Kind != permissions.PrincipalUser && principal.Kind != permissions.PrincipalGroup {
		return fmt.Errorf("role assignments support only user or group principals")
	}
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	const stmt = `
delete from principal_roles
where principal_kind = $1
  and principal_id = $2
  and role_id = $3
  and binding_values = $4::jsonb
returning role_id
`

	// Convert Go map to JSONB
	bvJSON, err := json.Marshal(bindingValues)
	if err != nil {
		return fmt.Errorf("marshal bindingValues: %w", err)
	}

	var deleted string
	err = s.pool.QueryRow(
		ctx,
		stmt,
		string(principal.Kind),
		principal.ID,
		roleID,
		bvJSON,
	).Scan(&deleted)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf(
				"role %q with bindingValues %+v was not assigned to principal %s",
				roleID,
				bindingValues,
				principal.ID,
			)
		}
		return fmt.Errorf("delete principal role assignment: %w", err)
	}

	return nil
}

func (s *Store) DeleteGrantsForOwner(ctx context.Context, ownerKind permissions.PrincipalKind, ownerID string) error {
	if ownerID == "" {
		return fmt.Errorf("owner ID is required")
	}

	const stmt = `delete from permission_grants where owner_kind = $1 and owner_id = $2`
	if _, err := s.pool.Exec(ctx, stmt, string(ownerKind), ownerID); err != nil {
		return fmt.Errorf("delete grants for owner: %w", err)
	}

	return nil
}

func (s *Store) DisableBuiltInRole(ctx context.Context, roleID string) error {
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	const stmt = `insert into disabled_builtin_roles (role_id) values ($1) on conflict (role_id) do nothing`
	if _, err := s.pool.Exec(ctx, stmt, roleID); err != nil {
		return fmt.Errorf("disable built in role: %w", err)
	}

	return nil
}

func (s *Store) EnableBuiltInRole(ctx context.Context, roleID string) error {
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	const stmt = `delete from disabled_builtin_roles where role_id = $1`
	if _, err := s.pool.Exec(ctx, stmt, roleID); err != nil {
		return fmt.Errorf("enable built in role: %w", err)
	}

	return nil
}

func (s *Store) DisabledBuiltInRoles(ctx context.Context) ([]string, error) {
	const query = `select role_id from disabled_builtin_roles order by role_id`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query disabled built in roles: %w", err)
	}
	defer rows.Close()

	roles := make([]string, 0)
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			return nil, fmt.Errorf("scan disabled built in role: %w", err)
		}
		roles = append(roles, roleID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate disabled built in roles: %w", err)
	}

	return roles, nil
}

func (s *Store) ListGrants(ctx context.Context, query permissions.GrantQuery) (permissions.GrantQueryResult, error) {
	var result permissions.GrantQueryResult

	// Build WHERE clause
	var conditions []string
	var args []any
	argID := 1

	if len(query.Principals) > 0 {
		var principalExprs []string
		for _, p := range query.Principals {
			principalExprs = append(principalExprs, fmt.Sprintf("(owner_kind = $%d and owner_id = $%d)", argID, argID+1))
			args = append(args, string(p.Kind), p.ID)
			argID += 2
		}
		conditions = append(conditions, "("+strings.Join(principalExprs, " or ")+")")
	}

	if len(query.TeamScopes) > 0 {
		var teamArgs []string
		for _, ts := range query.TeamScopes {
			teamArgs = append(teamArgs, fmt.Sprintf("$%d", argID))
			args = append(args, ts)
			argID++
		}
		conditions = append(conditions, fmt.Sprintf("team_scope in (%s)", strings.Join(teamArgs, ", ")))
	}

	if len(query.ObjectScopes) > 0 {
		var objArgs []string
		for _, os := range query.ObjectScopes {
			objArgs = append(objArgs, fmt.Sprintf("$%d", argID))
			args = append(args, os)
			argID++
		}
		conditions = append(conditions, fmt.Sprintf("object_scope in (%s)", strings.Join(objArgs, ", ")))
	}

	if len(query.Permissions) > 0 {
		var permArgs []string
		for _, p := range query.Permissions {
			permArgs = append(permArgs, fmt.Sprintf("$%d", argID))
			args = append(args, p)
			argID++
		}
		conditions = append(conditions, fmt.Sprintf("permission_name in (%s)", strings.Join(permArgs, ", ")))
	}

	if query.PermissionPrefix != "" {
		conditions = append(conditions, fmt.Sprintf("permission_name like $%d", argID))
		args = append(args, query.PermissionPrefix+"%")
		argID++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "where " + strings.Join(conditions, " and ")
	}

	// First, get total count
	countQuery := "select count(*) from permission_grants " + whereClause
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&result.TotalCount); err != nil {
		return result, fmt.Errorf("count grants: %w", err)
	}

	// Pagination
	if query.Cursor != "" {
		cursorVal, err := strconv.ParseInt(query.Cursor, 10, 64)
		if err != nil {
			return result, fmt.Errorf("invalid cursor: %w", err)
		}
		conditions = append(conditions, fmt.Sprintf("id > $%d", argID))
		args = append(args, cursorVal)
		argID++
		whereClause = "where " + strings.Join(conditions, " and ")
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 1000 {
		limit = 1000
	}

	sqlQuery := fmt.Sprintf(`
select
	id, owner_kind, owner_id, effect, team_scope, object_scope, permission_name, expires_at, field_allowlist, variable_spec
from permission_grants
%s
order by id asc
limit $%d
`, whereClause, argID)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, sqlQuery, args...)
	if err != nil {
		return result, fmt.Errorf("query grants list: %w", err)
	}
	defer rows.Close()

	grants := make([]permissions.Grant, 0, limit)
	var lastID int64
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
			&grant.ExpiresAt,
			&grant.RestrictedFields,
			&variableSpecRaw,
		); err != nil {
			return result, fmt.Errorf("scan grant: %w", err)
		}

		grant.OwnerKind = permissions.PrincipalKind(ownerKind)
		grant.Effect = permissions.Effect(effect)

		variableSpec := map[string]any{}
		if len(variableSpecRaw) > 0 {
			if err := json.Unmarshal(variableSpecRaw, &variableSpec); err != nil {
				return result, fmt.Errorf("unmarshal variable spec: %w", err)
			}
		}
		grant.VariableSpec = variableSpec

		grants = append(grants, grant)
		lastID = grant.ID
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate grants: %w", err)
	}

	result.Grants = grants
	if len(grants) == limit {
		result.NextCursor = strconv.FormatInt(lastID, 10)
	}

	return result, nil
}
