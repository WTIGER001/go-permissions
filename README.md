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
3. A sample suite under [samples](samples) for modeling scenarios.

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
permissionStore := inmemory.NewStore()
identityProvider := inmemory.NewIdentityProvider()
svc := permissions.NewService(permissionStore, identityProvider)

_ = svc.AllowUser(ctx, "user-1", "projects.view", nil)
_ = svc.AllowUserFor(ctx, "user-1", "projects.share", nil, 30*time.Minute)
ok, err := svc.HasSystemPermission(ctx, "user-1", "projects.view")
```

### Split identity and policy (external identity provider)

Use your own identity adapter plus a policy backend:

```go
svc := permissions.NewService(postgresStore, identityAdapter)
```

A concrete external identity adapter example is in [example_identity_adapter_test.go](example_identity_adapter_test.go).

## Main APIs

Defined in [service.go](service.go):

1. HasPermission
2. HasSystemPermission
3. HasTeamPermission
4. EffectivePermissions
5. PrincipalsWithPermission

Convenience write helpers:

1. AllowUser
2. DenyUser
3. AllowRole
4. AllowUserUntil / AllowUserFor
5. DenyUserUntil / DenyUserFor
6. AllowRoleUntil / AllowRoleFor
7. AssignRoleToUser

These require store write capabilities via:

1. GrantWriter
2. RoleAssignmentWriter

Defined in [store.go](store.go).

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

## Samples

Scenario samples live under [samples](samples), each in its own folder with:

1. a Markdown walkthrough
2. a main.go runnable example

## Testing and Build

Run tests:

go test ./...

Build all packages:

go build ./...

## Design Document

The detailed architecture and schema rationale is in [design.md](design.md).
