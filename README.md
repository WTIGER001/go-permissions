# go-permissions

A Go authorization library with:

1. Permission checks for system, team, and object scopes.
2. Deny-overrides-allow evaluation.
3. Role assignments, role expansion, and template bindings.
4. Pluggable identity and policy backends.
5. Utility APIs and a permission registry.

## Status

This library currently provides:

1. Core service APIs for permission evaluation.
2. Backends:
- in-memory store
- PostgreSQL store
- JSON file store
- cached wrapper store
3. An examples suite under [examples](examples) for modeling scenarios.

## Installation

From your project:

go get github.com/wtiger001/go-permissions

## Core Concepts

1. IdentityProvider: resolves user/group membership data.
2. PermissionStore: roles, grants, and policy graph data.
3. Service: authorization engine that combines identity and policy.
4. PermissionRegistry: catalog of known permission definitions.

Interfaces are defined in [store.go](store.go).

## Quick Start

### In-memory example

```go
ctx := context.Background()
svc := permissions.New()
svc.SetIdentityProvider(inmemory.NewIdentityProvider())
_ = svc.SetStore(inmemory.NewStore())

_ = svc.AllowUser(ctx, "user-1", "projects.view", nil)
_ = svc.AllowUserFor(ctx, "user-1", "projects.share", nil, 30*time.Minute)
ok, err := svc.HasSystemPermission(ctx, "user-1", "projects.view")
```

### Split identity and policy (external identity provider)

Use your own identity adapter plus a policy backend:

```go
svc := permissions.NewService(postgresStore, identityAdapter)
```

### Staged startup with built-ins

The staged setup API supports wiring identity/store later and auto-seeding built-ins when the store is set.

```go
ctx := context.Background()

svc := permissions.New()
svc.SetIdentityProvider(identityAdapter)

// Synthetic role IDs default to:
// - permissions.SyntheticRolePublic
// - permissions.SyntheticRoleAuthenticated
// - permissions.SyntheticRoleAdmin
// Override only if you need custom IDs.
// svc.SetSyntheticRoleIDs("custom.public", "custom.authenticated", "custom.admin")

svc.SetAdminGroupID("group.admins")
_ = svc.AddDefaultGrant(permissions.SyntheticRolePublic, "assets.read", "*")
_ = svc.AddDefaultGrant(permissions.SyntheticRoleAuthenticated, "profile.read", "*")
_ = svc.AddDefaultGrant(permissions.SyntheticRoleAdmin, "admin.read", "*")

// SetStore automatically calls SaveBuiltIns with the configured built-in grants.
if err := svc.SetStore(postgresStore); err != nil {
	return err
}

// Optional explicit call if you need to seed an additional one-off set.
if err := svc.SaveBuiltIns(ctx, extraBuiltIns); err != nil {
	return err
}
```

A concrete external identity adapter example is in [example_identity_adapter_test.go](example_identity_adapter_test.go).

### Production startup checklist

Recommended startup sequence for production services:

1. Construct the service (`svc := permissions.New()`).
2. Set identity provider (`svc.SetIdentityProvider(identityProvider)`).
3. Configure synthetic role IDs (`svc.SetSyntheticRoleIDs(...)`) and admin group (`svc.SetAdminGroupID(...)`) when used.
4. Configure built-in grants (`svc.SetBuiltInGrants(defaultBuiltIns)`).
5. Set the backing store (`svc.SetStore(store)`), which automatically triggers built-in seeding.
6. Start serving traffic only after step 5 succeeds.

Operational guidance:

1. Treat `SetStore` bootstrap failures as startup-fatal for strict authorization environments.
2. If your deployment policy allows degraded startup, gate protected endpoints until bootstrap succeeds.
3. Prefer retry with backoff for transient store connectivity errors before failing startup.
4. Keep built-in grants deterministic and code-defined so repeated startup remains idempotent.
5. Use explicit migrations/admin tooling for policy changes that should override existing manual policy.

## Main APIs

Defined in [service.go](service.go):

1. HasPermission
2. HasSystemPermission
3. HasTeamPermission
4. HasFieldPermission
5. FilterPermittedFields
6. EffectivePermissions
7. PrincipalsWithPermission

Convenience write helpers:

1. AllowUser
2. DenyUser
3. AllowRole
4. AllowUserUntil / AllowUserFor
5. DenyUserUntil / DenyUserFor
6. AllowRoleUntil / AllowRoleFor
7. AssignRoleToUser

Write operations are part of PermissionStore (see [store.go](store.go)).

### Field-Scoped Grants

Grants can optionally scope access with `Grant.RestrictedFields`.

1. Empty restricted list means the grant applies to all fields.
2. Non-empty restricted list means those paths (and nested subpaths) are excluded.
3. Indexed array paths (for example `items.0.name`) are not supported.

Field-aware APIs:

1. `svc.HasFieldPermission(ctx, req, "profile.email")`
2. `svc.FilterPermittedFields(ctx, req, []string{"profile.email", "profile.secret"})`

### Expiring Grants

Most grants are permanent and use:

1. AllowUser
2. DenyUser
3. AllowRole

For temporary access, use:

1. `...Until` when you have a fixed expiration timestamp.
2. `...For` when you have a TTL duration.

Example patterns:

- `svc.AllowUserUntil(ctx, userID, perm, objectID, expiresAt)`
- `svc.AllowUserFor(ctx, userID, perm, objectID, 30*time.Minute)`
- `svc.DenyUserFor(ctx, userID, perm, objectID, 15*time.Minute)`
- `svc.AllowRoleUntil(ctx, roleID, perm, objectID, expiresAt)`

## Backends

1. In-memory backend: [inmemory/store.go](inmemory/store.go)
2. PostgreSQL backend: [postgres/store.go](postgres/store.go)
3. JSON file backend: [jsonstore/store.go](jsonstore/store.go)
4. Cached wrapper backend: [cachedstore/store.go](cachedstore/store.go)

### Cached store

The cached wrapper memoizes read calls and invalidates on writes.

- Default TTL is 1 minute.
- Constructor:
- cachedstore.NewStore(baseStore)
- cachedstore.NewStoreWithTTL(baseStore, ttl)

## Permission Registry

Registry APIs are defined in [registry.go](registry.go):

1. Register / MustRegister
2. Get / Exists
3. List / ListByNamespace
4. Definition adapters on permission builder types

## Examples

Scenario examples live under [examples](examples) as flat test files:

1. one `<scenario>_test.go` file per scenario
2. one self-contained `Test...` function per file
3. a function-level comment describing the scenario

## Testing and Build

Run tests:

go test ./...

Build all packages:

go build ./...

## Design Document

The detailed architecture and schema rationale is in [design.md](design.md).
