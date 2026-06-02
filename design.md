# Permissions Design

## Problem Framing

The product has one system and many teams. Team 0 is a useful conceptual shorthand for the system, but the authorization model should treat system scope and team scope as first-class concepts instead of trying to force everything into a single opaque string.

The design below assumes:

- Permission checks are evaluated for exactly one team context at a time.
- System permissions and team permissions are separate in storage, but may both be considered when evaluating a request.
- Deny always wins.
- Groups can nest.
- Roles can grant roles.
- Roles may contain template variables, and bindings are supplied at assignment time using named parameters.
- The system should stay allow-focused and avoid parsing-heavy hot paths.
- Field permissions are a future extension and should not distort the base model.

## Recommendation

Use a normalized policy model in PostgreSQL, then project it into a small authorization service in Go.

The best tradeoff for performance and clarity is:

1. Store grants in structured columns rather than encoding everything into one string.
2. Precompute group and role expansion with closure tables.
3. Evaluate a request by resolving candidate principals first, then running a small set of indexed grant lookups.
4. Keep field-level permissions in a separate structure so the core permission check stays cheap.

## Canonical Permission Shape

Keep the logical permission shape as:

`<team>::<object>::<permission>`

Where:

- `team` is a concrete team id, `*` for all teams, or a template variable in role definitions.
- `object` is optional and may be empty or `*`.
- `permission` is the action name, such as `read`, `write`, `delete`, or `finops.reader`.

For the database and service API, prefer fields over string parsing:

- `team_scope`
- `object_scope`
- `permission_name`
- `field_allowlist` later

That keeps matching cheap and indexable.

## Data Model

### Core entities

```sql
create type principal_type as enum ('user', 'group', 'role');
create type grant_effect as enum ('allow', 'deny');

create table users (
	id bigserial primary key,
	external_key text unique,
	email text unique,
	display_name text not null,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table groups (
	id bigserial primary key,
	team_id bigint null,
	name text not null,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now(),
	unique (team_id, name)
);

create table roles (
	id bigserial primary key,
	code text not null unique,
	description text,
	built_in boolean not null default false,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);
```

### Membership and inheritance

Use closure tables so nested groups and role inheritance do not require recursive queries on every request.

```sql
create table group_members (
	group_id bigint not null references groups(id) on delete cascade,
	user_id bigint not null references users(id) on delete cascade,
	created_at timestamptz not null default now(),
	primary key (group_id, user_id)
);

create table group_closure (
	ancestor_group_id bigint not null references groups(id) on delete cascade,
	descendant_group_id bigint not null references groups(id) on delete cascade,
	depth int not null,
	primary key (ancestor_group_id, descendant_group_id)
);

create table role_inheritance (
	parent_role_id bigint not null references roles(id) on delete cascade,
	child_role_id bigint not null references roles(id) on delete cascade,
	primary key (parent_role_id, child_role_id)
);

create table role_closure (
	ancestor_role_id bigint not null references roles(id) on delete cascade,
	descendant_role_id bigint not null references roles(id) on delete cascade,
	depth int not null,
	primary key (ancestor_role_id, descendant_role_id)
);
```

### Role and permission assignment

All principals can hold permissions. Users and groups can also receive role assignments. Roles can contain permission templates and may inherit other roles.

```sql
create table principal_roles (
	id bigserial primary key,
	principal_kind principal_type not null,
	principal_id bigint not null,
	role_id bigint not null references roles(id) on delete cascade,
	binding_values jsonb not null default '{}'::jsonb,
	created_at timestamptz not null default now(),
	unique (principal_kind, principal_id, role_id, binding_values)
);

create table permission_grants (
	id bigserial primary key,
	owner_kind principal_type not null,
	owner_id bigint not null,
	effect grant_effect not null default 'allow',
	team_scope text not null,
	object_scope text null,
	permission_name text not null,
	expires_at timestamptz null,
	field_allowlist text[] null,
	variable_spec jsonb not null default '{}'::jsonb,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);
```

### Why this shape works

- `owner_kind` and `owner_id` let a single grant table serve users, groups, and roles.
- `team_scope` stores either a concrete team id, `*`, or a template token for role definitions.
- `object_scope` is nullable so global permission names are cheap.
- `expires_at` supports temporary grants without relying on implicit admin bypasses.
- `variable_spec` is the template metadata for role definitions, not runtime authorization data.
- `field_allowlist` is reserved for future field-level permissions and can stay null for now.

## Variable Binding Model

Role templates should stay stable and readable. Use named placeholders in the role definition, then bind them when assigning the role.

Example role grant:

```json
{
  "team_scope": "?team",
  "object_scope": "billing",
  "permission_name": "read",
  "variable_spec": {
	"team": "required"
  }
}
```

Example role assignment:

```json
{
  "team": 42
}
```

At evaluation time, the service resolves the binding into a concrete grant and then matches it against the current request.

## Matching Rules

For a request with `team_id`, `object`, and `permission_name`:

1. Expand all candidate principals for the user.
2. Collect all grants for those principals.
3. Expand role inheritance before evaluating grants.
4. Resolve role template bindings into concrete values.
5. Match grant to request.
6. If any matching deny exists, reject.
7. Otherwise accept if at least one matching allow exists.

Matching rules:

- Grants with `expires_at <= now()` are ignored.
- `*` in `team_scope` matches any concrete team.
- `*` in `object_scope` matches any object.
- `object_scope = null` means the permission is not object-specific.
- Exact matches are more specific than wildcard matches.
- Denies always override allows.

### Service Write Helpers For Expiring Grants

Default (no expiry):

1. `AllowUser`
2. `DenyUser`
3. `AllowRole`

With explicit expiration timestamp:

1. `AllowUserUntil`
2. `DenyUserUntil`
3. `AllowRoleUntil`

With TTL duration:

1. `AllowUserFor`
2. `DenyUserFor`
3. `AllowRoleFor`

## Why Not Store Everything In One String

Encoding all policy data into a single token looks simple at first, but it becomes expensive when you need:

- efficient filtering by team,
- deny precedence,
- role binding,
- field-level permissions,
- and future reporting queries like who has this permission.

Structured columns keep the design fast and keep the SQL readable.

## Service Design

The service should be small and self-contained.

```go
type PrincipalKind string

const (
	PrincipalUser  PrincipalKind = "user"
	PrincipalGroup PrincipalKind = "group"
	PrincipalRole  PrincipalKind = "role"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Request struct {
	UserID string
	TeamID *int64
	Object string
	Perm   string
}

type Grant struct {
	ID             int64
	OwnerKind      PrincipalKind
	OwnerID        string
	Effect         Effect
	TeamScope      string
	ObjectScope    *string
	PermissionName string
	ExpiresAt      *time.Time
	FieldAllowlist []string
}

type EffectivePermission struct {
	TeamScope      string
	ObjectScope    *string
	PermissionName string
	Source         PrincipalRef
	Effect         Effect
	Fields         []string
}

type IdentityProvider interface {
	GetUserGroups(ctx context.Context, userID string) ([]string, error)
	GetGroupMembers(ctx context.Context, groupID string) ([]string, error)
	IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error)
}

type PermissionStore interface {
	RoleDefinitions(ctx context.Context) ([]Role, error)
	RoleDefinition(ctx context.Context, roleID string) (Role, error)
	CreateRole(ctx context.Context, role Role) error
	UpdateRole(ctx context.Context, role Role) error
	DeleteRole(ctx context.Context, roleID string) error
	RoleAssignmentsForPrincipal(ctx context.Context, principal PrincipalRef) ([]RoleAssignment, error)
	AssignRole(ctx context.Context, principal PrincipalRef, roleID string, bindingValues map[string]any) error
	ExpandRoles(ctx context.Context, roleIDs []string) ([]string, error)
	GrantsForPrincipal(ctx context.Context, principal PrincipalRef) ([]Grant, error)
	GrantsForOwners(ctx context.Context, owners []PrincipalRef, req Request) ([]Grant, error)
	CreateGrant(ctx context.Context, grant Grant) error
	PrincipalsWithGrant(ctx context.Context, req Request) ([]PrincipalHit, error)
}

type AuthorizationService struct {
	identity    IdentityProvider
	permissions PermissionStore
}

// Service construction also supports staged setup:
// svc := permissions.New()
// svc.SetIdentityProvider(identityProvider)
// _ = svc.SetStore(permissionStore)
// svc.SetBuiltInGrants(defaultBuiltIns)
// _ = svc.SaveBuiltIns(ctx, defaultBuiltIns)
```

### Public API

The service should expose these methods:

```go
type Service interface {
	HasPermission(ctx context.Context, req Request) (bool, error)
	PrincipalsWithPermission(ctx context.Context, teamID *int64, object, perm string) ([]PrincipalHit, error)
	EffectivePermissions(ctx context.Context, userID string, teamID *int64) ([]EffectivePermission, error)
}
```

## Sample Implementation 1: HasPermission

This method collects all candidate principals, expands group and role inheritance, loads grants, and applies deny-first evaluation.

```go
func (s *AuthorizationService) HasPermission(ctx context.Context, req Request) (bool, error) {
	groupIDs, err := s.identity.GetUserGroups(ctx, req.UserID)
	if err != nil {
		return false, err
	}

	directRoleIDs := make([]string, 0)
	for _, groupID := range groupIDs {
		rows, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
		if err != nil {
			return false, err
		}
		for _, row := range rows {
			directRoleIDs = append(directRoleIDs, row.RoleID)
		}
	}
	userRows, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: req.UserID})
	if err != nil {
		return false, err
	}
	for _, row := range userRows {
		directRoleIDs = append(directRoleIDs, row.RoleID)
	}

	expandedRoleIDs, err := s.permissions.ExpandRoles(ctx, directRoleIDs)
	if err != nil {
		return false, err
	}

	owners := make([]PrincipalRef, 0, 1+len(groupIDs)+len(expandedRoleIDs))
	owners = append(owners, PrincipalRef{Kind: PrincipalUser, ID: req.UserID})
	for _, groupID := range groupIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
	}
	for _, roleID := range expandedRoleIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalRole, ID: roleID})
	}

	grants, err := s.permissions.GrantsForOwners(ctx, owners, req)
	if err != nil {
		return false, err
	}

	allowed := false
	for _, grant := range grants {
		if !grantMatchesRequest(grant, req) {
			continue
		}

		if grant.Effect == EffectDeny {
			return false, nil
		}
		allowed = true
	}

	return allowed, nil
}

func grantMatchesRequest(grant Grant, req Request) bool {
	if grant.PermissionName != req.Perm {
		return false
	}

	if req.TeamID != nil {
		if grant.TeamScope != "*" && grant.TeamScope != strconv.FormatInt(*req.TeamID, 10) {
			return false
		}
	} else if grant.TeamScope != "*" {
		return false
	}

	if grant.ObjectScope != nil && *grant.ObjectScope != "*" && *grant.ObjectScope != req.Object {
		return false
	}

	return true
}
```

## Sample Implementation 2: Who Has Permission

This query is best implemented as a reverse search over principals and their effective grants.

```go
type PrincipalHit struct {
	Kind  PrincipalKind
	ID    string
	Scope string
}

func (s *AuthorizationService) PrincipalsWithPermission(ctx context.Context, teamID *int64, object, perm string) ([]PrincipalHit, error) {
	return s.permissions.PrincipalsWithGrant(ctx, Request{
		TeamID: teamID,
		Object: object,
		Perm:   perm,
	})
}
```

The repository query should:

1. Find matching grants by `team_scope`, `object_scope`, and `permission_name`.
2. Expand group closure and role closure only for the principals owning those grants.
3. Exclude principals that also have a matching deny.

## Sample Implementation 3: EffectivePermissions

This method returns the permission set for one user in one team, deduplicated by source and with deny removed from the final allow list.

```go
func (s *AuthorizationService) EffectivePermissions(ctx context.Context, userID string, teamID *int64) ([]EffectivePermission, error) {
	groupIDs, err := s.identity.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	directRoleIDs := make([]string, 0)
	for _, groupID := range groupIDs {
		rows, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			directRoleIDs = append(directRoleIDs, row.RoleID)
		}
	}
	userRows, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: userID})
	if err != nil {
		return nil, err
	}
	for _, row := range userRows {
		directRoleIDs = append(directRoleIDs, row.RoleID)
	}

	expandedRoleIDs, err := s.permissions.ExpandRoles(ctx, directRoleIDs)
	if err != nil {
		return nil, err
	}

	owners := make([]PrincipalRef, 0, 1+len(groupIDs)+len(expandedRoleIDs))
	owners = append(owners, PrincipalRef{Kind: PrincipalUser, ID: userID})
	for _, groupID := range groupIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
	}
	for _, roleID := range expandedRoleIDs {
		owners = append(owners, PrincipalRef{Kind: PrincipalRole, ID: roleID})
	}

	grants, err := s.permissions.GrantsForOwners(ctx, owners, Request{UserID: userID, TeamID: teamID})
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	denied := map[string]bool{}
	result := make([]EffectivePermission, 0, len(grants))

	for _, grant := range grants {
		if teamID != nil && grant.TeamScope != "*" && grant.TeamScope != strconv.FormatInt(*teamID, 10) {
			continue
		}
		if teamID == nil && grant.TeamScope != "*" {
			continue
		}

		key := strings.Join([]string{grant.TeamScope, derefOrEmpty(grant.ObjectScope), grant.PermissionName}, "::")

		if grant.Effect == EffectDeny {
			denied[key] = true
			continue
		}

		if denied[key] || seen[key] {
			continue
		}

		seen[key] = true
		result = append(result, EffectivePermission{
			TeamScope:      grant.TeamScope,
			ObjectScope:    grant.ObjectScope,
			PermissionName: grant.PermissionName,
			Source:         PrincipalRef{Kind: grant.OwnerKind, ID: grant.OwnerID},
			Effect:         grant.Effect,
			Fields:         append([]string(nil), grant.FieldAllowlist...),
		})
	}

	return result, nil
}
```

## Reverse Lookup Query Strategy

To answer “who has this permission?”, do not scan all users.

Instead:

1. Find matching grants first.
2. Expand the owning principal graph only from those grants.
3. Resolve deny matches early.
4. Return users, groups, and roles separately.

That keeps the result set bounded by relevant policy data instead of tenant size.

## SQL Patterns For pgxv5

### User group lookup

```sql
select gc.ancestor_group_id
from group_members gm
join group_closure gc on gc.descendant_group_id = gm.group_id
where gm.user_id = $1;
```

### Role lookup from users and groups

```sql
select distinct pr.role_id, pr.binding_values
from principal_roles pr
where (pr.principal_kind = 'user' and pr.principal_id = $1)
   or (pr.principal_kind = 'group' and pr.principal_id = any($2::bigint[]));
```

### Role expansion

```sql
select distinct rc.descendant_role_id
from role_closure rc
where rc.ancestor_role_id = any($1::bigint[]);
```

### Grant lookup

```sql
select id, owner_kind, owner_id, effect, team_scope, object_scope, permission_name, field_allowlist, variable_spec
from permission_grants
where owner_kind = any($1::principal_type[])
  and owner_id = any($2::bigint[])
  and permission_name = $3
  and (team_scope = '*' or team_scope = $4::text)
  and (object_scope is null or object_scope = '*' or object_scope = $5::text);
```

## Indexing

At this scale, indexes matter more than exotic algorithms.

Recommended indexes:

```sql
create index idx_group_members_user on group_members (user_id, group_id);
create index idx_group_closure_descendant on group_closure (descendant_group_id, ancestor_group_id);
create index idx_role_assignments_principal on principal_roles (principal_kind, principal_id, role_id);
create index idx_role_closure_ancestor on role_closure (ancestor_role_id, descendant_role_id);
create index idx_permission_grants_owner_perm on permission_grants (owner_kind, owner_id, permission_name);
create index idx_permission_grants_match on permission_grants (team_scope, object_scope, permission_name, effect);
```

If read traffic grows, add a small cache table or Redis layer keyed by `(user_id, team_id)` and invalidate it on grant changes. With the stated scale, the indexed SQL path should already be fast enough for most requests.

## Field-Level Permissions

Field-level permissions should be a second-stage filter, not part of the core permission grant lookup.

Recommended structure:

```sql
create table permission_field_grants (
	id bigserial primary key,
	grant_id bigint not null references permission_grants(id) on delete cascade,
	field_name text not null,
	effect grant_effect not null default 'allow',
	unique (grant_id, field_name, effect)
);
```

Behavior:

- If no field grants exist, the user gets full access for that permission.
- If field grants exist, treat them as an allowlist.
- Deny still wins.
- Keep field filtering separate from the base permission check so common requests stay cheap.

## Recommended Evaluation Order

1. Resolve the user's direct grants.
2. Resolve grants from all groups the user belongs to, including nested groups.
3. Resolve all assigned roles from the user and groups.
4. Expand inherited roles.
5. Expand role bindings into concrete grant candidates.
6. Apply deny-first matching.
7. If the request asks for fields, apply field filtering after the base permission is granted.

## Practical Notes

- Keep team ids as integers everywhere except the policy template layer, where `*` and `?` are allowed.
- Prefer one small authorization package in Go rather than spreading checks throughout the application.
- Make permission evaluation pure and deterministic so it is easy to test.
- Use transactionally consistent updates for grants, memberships, and closure tables.
- If role or group updates are frequent, rebuild closure rows in the same transaction or in a serialized background job.

## Testing Plan

Minimum tests to add once the implementation exists:

1. Direct allow on user.
2. Group allow through nested group.
3. Role allow through user assignment.
4. Role allow through group assignment.
5. Role inheritance chain.
6. Matching deny overrides allow.
7. Team wildcard matches all teams.
8. Object wildcard matches any object.
9. Field-level filter only affects field output, not base permission truth.

## Suggested Next Step

If you want, the next useful artifact is a concrete PostgreSQL schema migration plus a Go package skeleton with repository interfaces and one fully working `HasPermission` implementation.

## OPA For Conditional Role Grants

Using OPA for conditional grants is a strong fit for advanced policy logic, as long as you keep role membership expansion and direct permission checks in your fast SQL path.

Recommended split:

1. PostgreSQL remains source of truth for users, groups, roles, grants, and bindings.
2. OPA decides whether a conditional role assignment is active for a request context.
3. The authorization service merges active conditional roles with normal roles before permission evaluation.

This keeps OPA focused on context-aware decisions (risk, region, resource tags, time windows), while preserving your performant base model.

### Conditional Role Assignment Model

Add a new table that links a principal to a role with an optional policy reference.

```sql
create table conditional_role_assignments (
		id bigserial primary key,
		principal_kind principal_type not null,
		principal_id bigint not null,
		role_id bigint not null references roles(id) on delete cascade,
		policy_key text not null,
		binding_values jsonb not null default '{}'::jsonb,
		enabled boolean not null default true,
		valid_from timestamptz null,
		valid_until timestamptz null,
		created_at timestamptz not null default now(),
		updated_at timestamptz not null default now()
);

create index idx_conditional_role_principal
		on conditional_role_assignments (principal_kind, principal_id, enabled);

create index idx_conditional_role_policy
		on conditional_role_assignments (policy_key, enabled);
```

Notes:

- `policy_key` points to a policy bundle/rule in OPA.
- `binding_values` works like your existing role variable bindings.
- `valid_from` and `valid_until` let you short-circuit obvious time failures before OPA.

### OPA Input Contract

Use a stable input envelope so Rego can evolve without API churn.

```json
{
	"request": {
		"user_id": 123,
		"team_id": 42,
		"object": "billing-account",
		"permission": "read",
		"action": "assume-role"
	},
	"principal": {
		"kind": "user",
		"id": 123,
		"groups": [9, 11],
		"current_roles": [2, 7]
	},
	"candidate_role": {
		"id": 15,
		"code": "team_finops_reader",
		"binding_values": {"team": 42}
	},
	"context": {
		"now": "2026-05-21T19:01:00Z",
		"mfa": true,
		"ip": "203.0.113.10",
		"region": "us-east-1",
		"resource_tags": {
			"pci": "false",
			"env": "prod"
		}
	}
}
```

Keep this input small and deterministic. For large context objects, pre-filter upstream and pass only fields needed by policy.

### OPA Decision Shape

Have OPA return a simple decision object that your service can merge safely.

```json
{
	"allow": true,
	"reason": "mfa_and_team_match",
	"ttl_seconds": 30
}
```

`ttl_seconds` enables short-lived decision caching for repeated checks.

### Rego Example

Example package for conditional role assumption:

```rego
package authz.conditional_roles

default decision := {
	"allow": false,
	"reason": "default_deny",
	"ttl_seconds": 15,
}

decision := {
	"allow": true,
	"reason": "mfa_and_team_match",
	"ttl_seconds": 30,
} if {
	input.request.action == "assume-role"
	input.context.mfa == true
	input.request.team_id == input.candidate_role.binding_values.team
	not blocked_region
}

blocked_region if {
	input.context.region == "restricted-region"
}
```

### Service Flow With OPA

Adjust your check pipeline:

1. Resolve direct groups and direct roles from SQL.
2. Load candidate conditional role assignments for user and groups.
3. Evaluate candidate assignments through OPA.
4. Keep only OPA-allowed assignments.
5. Expand inherited roles through `role_closure`.
6. Resolve grants and evaluate with existing deny-first logic.

This preserves your current model and inserts OPA only where needed.

### Go Integration Sketch

```go
type OPAClient interface {
		EvaluateConditionalRole(ctx context.Context, policyKey string, input any) (OPADecision, error)
}

type OPADecision struct {
		Allow      bool
		Reason     string
		TTLSeconds int
}

func (s *AuthorizationService) resolveConditionalRoles(
		ctx context.Context,
		userID int64,
		groupIDs []int64,
		req Request,
		contextMap map[string]any,
) ([]int64, error) {
		rows, err := s.store.ListConditionalRoleAssignments(ctx, userID, groupIDs)
		if err != nil {
				return nil, err
		}

		allowedRoleIDs := make([]int64, 0, len(rows))
		for _, row := range rows {
				input := map[string]any{
						"request": map[string]any{
								"user_id":    req.UserID,
								"team_id":    req.TeamID,
								"object":     req.Object,
								"permission": req.Perm,
								"action":     "assume-role",
						},
						"principal": map[string]any{
								"kind":   row.PrincipalKind,
								"id":     row.PrincipalID,
								"groups": groupIDs,
						},
						"candidate_role": map[string]any{
								"id":             row.RoleID,
								"binding_values": row.BindingValues,
						},
						"context": contextMap,
				}

				decision, err := s.opa.EvaluateConditionalRole(ctx, row.PolicyKey, input)
				if err != nil {
						return nil, err
				}
				if decision.Allow {
						allowedRoleIDs = append(allowedRoleIDs, row.RoleID)
				}
		}

		return allowedRoleIDs, nil
}
```

Then merge `allowedRoleIDs` into your normal role set before calling `ExpandRoles`.

### Performance Guidance

To keep this fast at your scale:

1. Evaluate OPA only for candidate conditional assignments, not every grant.
2. Cache OPA decision by hash of `(policy_key, normalized_input)` for `ttl_seconds`.
3. Pre-check `enabled`, `valid_from`, and `valid_until` in SQL before OPA.
4. Bound context payload size.
5. Use local OPA sidecar or embedded evaluator to avoid network hop latency.

### Failure Mode Strategy

Choose one mode per endpoint and keep it explicit:

- `fail_closed`: if OPA is unavailable, conditional role is denied.
- `fail_open_for_read_only`: only for low-risk read endpoints.

Given orchestration and cloud management risk, default to `fail_closed`.

### Auditability

Record each conditional role decision with:

- principal,
- role,
- policy_key,
- decision,
- reason,
- request correlation id,
- timestamp.

This is critical for explaining why a user did or did not get a role at runtime.

## ABAC Extension (Future)

Keep RBAC and GBAC as the baseline model. Add ABAC as an optional condition layer for context-sensitive decisions.

### Recommended Hybrid Model

1. Resolve user, groups, and roles using existing closure tables.
2. Find matching candidate grants using `permission_name`, `team_scope`, and `object_scope`.
3. Evaluate ABAC conditions only for matched candidates.
4. Apply deny-first semantics across both unconditional and conditional grants.
5. Return allow only when at least one effective allow remains.

This keeps most requests on fast indexed SQL and limits policy engine usage to a small candidate set.

### Minimal Schema Hook

Attach optional policy references to grants rather than replacing the grant model:

```sql
alter table permission_grants
	add column condition_policy_key text null,
	add column condition_mode text null;

create index idx_permission_grants_condition_policy
	on permission_grants (condition_policy_key)
	where condition_policy_key is not null;
```

Notes:

- `condition_policy_key` points to a policy (OPA/Rego or internal evaluator).
- `condition_mode` can encode behavior like `required` or `unless` if needed later.
- Null condition fields mean the grant is unconditional and evaluated in pure SQL.

### ABAC Input Contract

Keep policy input small and deterministic:

```json
{
	"request": {
		"user_id": 123,
		"team_id": 42,
		"object": "invoice",
		"permission": "Billing.Costs.View",
		"action": "authorize"
	},
	"principal": {
		"groups": [9, 11],
		"roles": [2, 7]
	},
	"resource": {
		"owner_team_id": 42,
		"classification": "internal"
	},
	"context": {
		"mfa": true,
		"region": "us-east-1",
		"now": "2026-05-25T14:00:00Z"
	}
}
```

### Evaluation Rules

- ABAC should be evaluated only after RBAC and GBAC narrowing.
- Deny still overrides allow.
- Missing policy decision should default to deny for privileged permissions.
- Cache policy decisions for short TTL values using normalized input.

### Rollout Plan

1. Start with pure RBAC and GBAC.
2. Enable ABAC for high-risk permissions first (cost visibility, admin actions, impersonation).
3. Add audit records including `policy_key`, decision result, and reason.
4. Keep ABAC optional per permission to avoid policy sprawl.

## Go Interaction Approach

This section describes how application developers declare and use permissions in Go.
Each permission is a first-class struct with strongly typed check methods.

### Design Boundary

This API is for binary authorization checks.

- Declarations define capability and scope.
- Checks answer whether the caller is authorized.
- Approval workflows and policy-specific business logic are handled in separate systems.

### Core Declaration Patterns

#### Case 1: System Permission

Use for global checks that are not team- or object-scoped.

```go
var SystemCostReportView = policy.NewSystemPermission(
	"finops.system-cost-report.view", // Permission ID
	"Finops",                        // Namespace / Feature / Category
	"View System Cost Report",       // Display name
	"A description",                 // Description (markdown allowed)
	true,                            // Whether admin override is allowed
)

if SystemCostReportView.Can(ctx, u) {
	// Do something
}
```

#### Case 2: Team Permission

Use for checks scoped to a team.

```go
var TeamCostReportView = policy.NewTeamPermission(
	"finops.team-cost-report.view",
	"Finops",
	"View Team Cost Report",
	"A description",
	true,
)

if TeamCostReportView.Can(ctx, u, teamID) {
	// Do something
}
```

#### Case 3: Object Permission

Use when access is tied to one object instance.

```go
var UserView = policy.NewObjectPermission(
	"user.user.view",
	"User",
	"View a User",
	"A description",
	true,
)

if UserView.Can(ctx, u, userID) {
	// Do something
}
```

Sample IDs:

- `user.user.view`
- `user.group.view`
- `user.group-members.view`
- `user.group-members.update`
- `team.team.create`

#### Case 4: Hierarchical Object Permission

Use when checks depend on a leaf object plus its parent lineage.

```go
var FileRead = policy.NewObjectPermission(
	"folders.file.read",
	"Folders",
	"Read File Contents",
	"A description",
	true,
)

// Order is explicit: leaf -> parent -> grandparent
if FileRead.Can(ctx, u, itemID, parentID, grandParentID) {
	// Do something
}
```

Sample IDs:

- `folders.file.read`
- `folders.folder.read`
- `folders.folder.list`

### Batch Operations

For same-type targets, expose `Any`, `All`, and `Filter`.

#### Any

Returns true if at least one target is authorized.

```go
ok, err := UserView.Any(ctx, u, userID1, userID2, userID3)
if err != nil {
	return err
}
if ok {
	// User can access at least one target
}
```

#### All

Returns true only if every target is authorized.

```go
ok, err := UserView.All(ctx, u, userID1, userID2, userID3)
if err != nil {
	return err
}
if ok {
	// User can access all targets
}
```

#### Filter

Returns only the targets the user can access.

```go
allowed, err := UserView.Filter(ctx, u, userID1, userID2, userID3)
if err != nil {
	return err
}
// allowed preserves input order and includes only authorized IDs
```

Recommended semantics:

- `Any` with empty input returns `false`.
- `All` with empty input returns `true`.
- `Filter` with empty input returns an empty result.
- Methods short-circuit where possible and return `(value, error)`.

### Hierarchical Batch Operation

For list endpoints where many leaf nodes share parent lineage, use a specialized helper.

```go
allowedLeafIDs, err := FileRead.HierarallhicalFilter(ctx, u, leafIDs, sharedParentPath)
if err != nil {
	return err
}
```

Where:

- `leafIDs` are checked independently.
- `sharedParentPath` is applied to each leaf check.

Recommended semantics:

- Preserve input order in output.
- Empty `leafIDs` returns an empty result.
- Empty `sharedParentPath` is valid and means leaf-only checks.
- Parent path order is fixed and documented.

### Any vs Hierarchical

- `Hierarchical` defines one check shape across a lineage.
- `Any` and `All` define how multiple checks are combined.
- `Any` can be used over many hierarchical checks.

### Options

#### WithFields([]string)

Restricts readable or writable fields for this permission.


## Thoughts to Resolve

- Multiple Scopes... not just user and team. Maybe variable... 
- How to handle policy based permissions
- Default Role pattern
- Func Receiver to filter? 
