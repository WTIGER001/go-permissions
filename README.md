# go-permissions

A high-performance, release-safe Go authorization library featuring:

1. **In-Memory Built-In Roles (`builtin.*`)**: Built-in system roles and default grants managed entirely in memory with zero SQL seeding or migration overhead.
2. **PostgreSQL Custom Roles & Overrides**: Custom roles, user/group role assignments, and runtime administrative toggles (`disabled_builtin_roles`) stored in PostgreSQL.
3. **Multi-Scope Evaluation**: Permission checks for system, team, and object scopes with deny-overrides-allow logic.
4. **Service Proxying**: Complete encapsulation—clients interact exclusively with `permissions.Service`.
5. **Documentation Guides**: Comprehensive guides including [Getting Started](docs/getting_started.md) and [Roles Architecture](docs/roles_architecture.md).

---

## Installation

```bash
go get github.com/wtiger001/go-permissions
```

---

## Core Concepts

1. **`Service`**: The primary authorization engine and client entry point. All role management and permission checks proxy through `Service`.
2. **Built-In Roles**: System roles defined in Go code. IDs MUST begin with the prefix `builtin.` (e.g. `builtin.public`, `builtin.backup-operator`).
3. **Synthetic Roles**: Special root built-in roles (`builtin.public`, `builtin.authenticated`, `builtin.admin`) dynamically evaluated based on request context.
4. **`IdentityProvider`**: Resolves user and group membership data from your application identity system (Keycloak, Auth0, DB).
5. **`PermissionStore`**: Stores custom roles, role assignments, custom grants, and disabled built-in role records.

---

## Quick Start

See the detailed **[Getting Started Guide](docs/getting_started.md)** for step-by-step instructions.

```go
package main

import (
	"context"
	"fmt"

	"github.com/wtiger001/go-permissions"
)

func main() {
	ctx := context.Background()
	svc := permissions.New()

	// 1. Register a built-in feature role (must start with "builtin.")
	svc.BootstrapBuiltInRole(ctx, permissions.Role{
		ID:          "builtin.editor",
		Name:        "Editor",
		Permissions: []string{"article.create", "article.edit"},
	})

	// 2. Wire built-in role to synthetic authenticated role
	svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAuthenticated, "builtin.editor")

	// 3. Evaluate permission for an authenticated user
	allowed, err := svc.HasPermission(ctx, permissions.Request{
		UserID: "user_123", // Authenticated user
		Perm:   "article.edit",
	})
	if err == nil && allowed {
		fmt.Println("Access Granted!")
	}
}
```

---

## Documentation

- **[Getting Started Guide](docs/getting_started.md)**: Tutorial on setting up identity adapters, role inheritance, and API middleware checks.
- **[Roles Architecture](docs/roles_architecture.md)**: Deep dive into the dual in-memory/database model and runtime disable toggles.
- **[Developer Implementation Guide](docs/developer_guide.md)**: Best practices for implementing scope checks and registering permissions.
- **[Design Rationale](design.md)**: Original design document and evaluation mechanics.

---

## Testing and Build

Run unit tests across all backends:

```bash
go test ./...
```
