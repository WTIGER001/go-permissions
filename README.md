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

1. IdentityResolver: resolves user to group membership.
2. PolicyStore: roles, grants, and policy graph data.
3. Service: authorization engine that combines identity and policy.
4. PermissionRegistry: catalog of known permission definitions.

Interfaces are defined in [store.go](store.go).

## Quick Start

### In-memory example

```go
ctx := context.Background()
store := inmemory.NewStore()
svc := permissions.NewService(store)

_ = svc.AllowUser(ctx, "user-1", "projects.view", nil)
ok, err := svc.HasSystemPermission(ctx, "user-1", "projects.view")
```

### Split identity and policy (external identity provider)

Use your own identity adapter plus a policy backend:

```go
svc := permissions.NewServiceWithIdentity(identityAdapter, postgresStore)
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
4. AssignRoleToUser

These require store write capabilities via:

1. GrantWriter
2. RoleAssignmentWriter

Defined in [store.go](store.go).

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
