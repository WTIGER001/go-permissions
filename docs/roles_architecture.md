# Architectural Design: In-Memory Built-In & Custom Roles

This document outlines the architecture for managing **Built-In (System-Managed) Roles** alongside **Custom Roles** in `go-permissions`.

---

## 1. Architectural Principles

1. **In-Memory Built-In Roles**: All system-managed built-in roles and their default grants are declared in code and held in memory (`builtInRegistry`). They require zero database seeding or SQL schema migrations during application deployments.
2. **Naming Prefix Standard**: All built-in role IDs MUST begin with the prefix `builtin.` (e.g. `builtin.public`, `builtin.backup-operator`). This allows instant, high-performance prefix-based routing across the permission engine.
3. **Database Overrides (`disabled_builtin_roles`)**: Built-in roles are immutable at runtime, but administrators can disable any built-in role (including synthetic roles like `builtin.admin`). Disabling is persisted in a lightweight PostgreSQL table (`disabled_builtin_roles`) and checked via a fast 5-second in-memory TTL cache.
4. **Service Proxying**: Clients interact exclusively with `permissions.Service`. The service proxies role and grant management operations, combining in-memory built-in definitions with store-persisted custom roles.

---

## 2. Dual-Layer Storage Model

```mermaid
graph TD
    subgraph In-Memory Layer (Code Managed)
        BIR[Built-In Roles: builtin.*]
        BIG[Built-In Grants]
        SYN[Synthetic Roles: builtin.public, builtin.authenticated, builtin.admin]
    end

    subgraph Database Layer (PostgreSQL)
        DIS[disabled_builtin_roles]
        CR[roles: Custom Roles]
        PG[permission_grants: Custom & User Grants]
        PR[principal_roles: User/Group Assignments]
    end

    SVC[permissions.Service Proxy] --> BIR
    SVC --> BIG
    SVC --> DIS
    SVC --> CR
    SVC --> PG
    SVC --> PR
```

---

## 3. The Role Lifecycle & Registration

### 3.1 Registering Built-In Roles (In-Code)
Developers declare built-in roles in application code. Built-in role IDs MUST start with `builtin.`:

```go
package auth

import "github.com/wtiger001/go-permissions"

var (
	RoleBackupOperator = permissions.Role{
		ID:          "builtin.backup-operator",
		Name:        "Backup Operator",
		Description: "Allows running, listing, and downloading system backups.",
		Permissions: []string{
			"backup.backups.list",
			"backup.backup.run",
			"backup.backup.download",
		},
	}
)

func Init(svc *permissions.Service) {
	svc.BootstrapBuiltInRole(context.Background(), RoleBackupOperator)
}
```

### 3.2 Administrative Toggles: Disabling Built-In Roles
If an administrator revokes a built-in role, they call `DisableBuiltInRole`:

```go
// Disables the role system-wide by writing to disabled_builtin_roles table
svc.DisableBuiltInRole(ctx, "builtin.backup-operator")
```

The evaluation engine checks the in-memory 5-second TTL cache for disabled roles and skips evaluating assignments and grants for disabled roles.

---

## 4. Customizing via Inheritance & Deny Overrides

Admins can create **Custom Roles** in PostgreSQL that inherit built-in roles:

1. **Create Custom Role**: Admin creates `role.custom-operator` in PostgreSQL.
2. **Inherit Built-In Role**: Link them in code or via service API:
   ```go
   svc.AddRoleInheritance(ctx, "role.custom-operator", "builtin.backup-operator")
   ```
3. **Add Deny Override**: Add a direct `deny` grant to `role.custom-operator` in PostgreSQL to restrict downloading:
   ```go
   svc.EnsureGrantForOwner(ctx, permissions.Grant{
       OwnerKind:      permissions.PrincipalRole,
       OwnerID:        "role.custom-operator",
       Effect:         permissions.EffectDeny,
       TeamScope:      "*",
       PermissionName: "backup.backup.download",
   })
   ```

### Advantages
- **Zero Database Seeding**: Updating software versions with new built-in roles or permissions requires no SQL migrations.
- **Instant Propagation**: Inheritance automatically propagates newly added permissions from built-in roles to custom child roles.
- **Strict Precedence**: Custom DB deny overrides always take precedence over built-in allow grants.
