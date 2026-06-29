# Getting Started with `go-permissions`

`go-permissions` is a high-performance, release-safe authorization library for Go applications. It manages built-in system roles and default grants in memory while tracking custom roles, group/user assignments, and administrative overrides in PostgreSQL or other stores.

---

## 1. Core Concepts

- **Built-In Roles (`builtin.*`)**: System-managed roles declared in Go code. They exist entirely in memory and require zero database migrations or seeding scripts.
- **Synthetic Roles**: Special root built-in roles (`builtin.public`, `builtin.authenticated`, `builtin.admin`) dynamically evaluated based on request context.
- **Custom Roles**: Administrative roles created at runtime and persisted in PostgreSQL.
- **Disabled Built-In Roles (`disabled_builtin_roles`)**: A database table tracking built-in roles that admins have disabled at runtime. Checked via a fast 5-second in-memory TTL cache.

---

## 2. Quickstart Implementation

### Step 1: Initialize the Service & Identity Adapter

Wire `permissions.Service` with your custom `IdentityProvider` implementation and policy store.

```go
package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/postgres"
)

type ApplicationIdentity struct{}

func (a ApplicationIdentity) GetUserGroups(ctx context.Context, userID string) ([]string, error) {
	if userID == "admin_user" {
		return []string{"group.admins"}, nil
	}
	return []string{"group.members"}, nil
}

func (a ApplicationIdentity) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) { return nil, nil }
func (a ApplicationIdentity) IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error) { return false, nil }

func main() {
	ctx := context.Background()

	// 1. Connect to PostgreSQL
	dbPool, _ := pgxpool.New(ctx, "postgres://user:pass@localhost:5432/mydb")
	store := postgres.NewStore(dbPool)
	store.EnsureSchema(ctx)

	// 2. Instantiate Service (Clients interact exclusively with Service)
	identity := ApplicationIdentity{}
	svc := permissions.NewServiceWithIdentity(identity, store)

	// 3. Configure Administrative Group for Synthetic Admin Role
	svc.SetAdminGroupID("group.admins")
}
```

---

### Step 2: Declare Built-In Roles and Inheritance

Register your application's built-in roles and wire them to synthetic root roles (`builtin.public`, `builtin.authenticated`, `builtin.admin`):

```go
func SetupRoles(svc *permissions.Service) {
	ctx := context.Background()

	// 1. Register Built-In Feature Roles (IDs must start with "builtin.")
	svc.BootstrapBuiltInRole(ctx, permissions.Role{
		ID:          "builtin.team-member",
		Name:        "Team Member",
		Description: "Base permissions for standard team members",
		Permissions: []string{"team.dashboard.read", "team.profile.update"},
	})

	svc.BootstrapBuiltInRole(ctx, permissions.Role{
		ID:          "builtin.backup-operator",
		Name:        "Backup Operator",
		Description: "Allows managing and executing system backups",
		Permissions: []string{"backup.backup.run", "backup.backups.list"},
	})

	// 2. Wire Feature Roles into Synthetic Root Roles via In-Memory Inheritance
	// Public users get public reader permissions
	svc.AddDefaultGrant(permissions.SyntheticRolePublic, "system.health.read", "*")

	// Authenticated users inherit Synthetic Public + Team Member permissions
	svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAuthenticated, permissions.SyntheticRolePublic)
	svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAuthenticated, "builtin.team-member")

	// Admin users inherit Synthetic Authenticated + Backup Operator permissions
	svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAdmin, permissions.SyntheticRoleAuthenticated)
	svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAdmin, "builtin.backup-operator")
}
```

---

### Step 3: Enforce Permission Checks in API Handlers

Check permissions by constructing a `permissions.Request`. Indicate authentication state using `UserID`:

```go
func HandleBackupRun(svc *permissions.Service, currentUserID string) {
	ctx := context.Background()

	// Perform permission check
	allowed, err := svc.HasPermission(ctx, permissions.Request{
		UserID: currentUserID, // Pass "" for anonymous, user ID for logged in users
		Perm:   "backup.backup.run",
	})
	if err != nil || !allowed {
		fmt.Println("Access Denied!")
		return
	}

	fmt.Println("Access Granted! Running backup...")
}
```

---

### Step 4: Manage Custom Roles & Administrative Toggles

Clients use `Service` proxy methods to list, create, or disable roles:

```go
func AdministrativeOperations(svc *permissions.Service) {
	ctx := context.Background()

	// List all active roles (combines in-memory built-ins and DB custom roles)
	roles, _ := svc.RoleDefinitions(ctx)
	for _, r := range roles {
		fmt.Printf("Role: %s (BuiltIn: %t, Disabled: %t)\n", r.ID, r.BuiltIn, r.IsDisabled)
	}

	// Disable a built-in role at runtime (stored in disabled_builtin_roles table)
	svc.DisableBuiltInRole(ctx, "builtin.backup-operator")

	// Re-enable a built-in role
	svc.EnableBuiltInRole(ctx, "builtin.backup-operator")
}
```
