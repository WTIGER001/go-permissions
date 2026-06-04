# Developer Implementation Guide: Authorization with `go-permissions`

This guide outlines how developers implement permission checks, register new permissions, and seed roles in application services. It assumes the core infrastructure (PostgreSQL database, database migrations, and dependency injection of the `permissions.Service` instance) has already been fully set up.

---

## 3-Step Implementation Workflow

To enforce authorization for any new feature, follow this simple 3-step workflow:
1. **Create and Register Permissions:** Define what action is being authorized and at what scope.
2. **Assign Permissions to Built-in Roles:** Define which roles automatically inherit the new permission at startup.
3. **Make Permission Checks:** Enforce the check at runtime inside the endpoint implementation.

---

## Step 1: Create and Register Permissions

Permissions are defined under a specific **Scope** and **Namespace** to keep them structured and fast to query. 

### 1.1 Choose the Appropriate Scope
- **System Scope (`system`):** Actions that apply globally across the entire platform (e.g., viewing global system costs, managing system settings).
- **Team Scope (`team`):** Actions restricted to a single team context (e.g., viewing team billing, adding team members).
- **Object Scope (`object`):** Actions restricted to a specific business resource instance (e.g., reading a specific file, deleting a specific repository).

### 1.2 Declare and Register in Go
Register new permissions in an initialization block using `PermissionDefinition` and the global `PermissionRegistry`:

```go
package auth

import (
	"github.com/wtiger001/go-permissions"
)

var Registry = permissions.NewPermissionRegistry()

var (
	// System Scope Permission
	PermSystemCostView = permissions.PermissionDefinition{
		ID:          "finops.system-cost-report.view",
		Scope:       permissions.PermissionScopeSystem,
		Namespace:   "finops",
		Name:        "View System Cost Report",
		Description: "Allows viewing system-wide global cost reporting.",
	}

	// Team Scope Permission
	PermTeamBillingRead = permissions.PermissionDefinition{
		ID:          "billing.team-billing.read",
		Scope:       permissions.PermissionScopeTeam,
		Namespace:   "billing",
		Name:        "Read Team Billing Info",
		Description: "Allows reading team-specific billing invoices.",
	}

	// Object Scope Permission
	PermFileRead = permissions.PermissionDefinition{
		ID:          "folders.file.read",
		Scope:       permissions.PermissionScopeObject,
		Namespace:   "folders",
		Name:        "Read File Contents",
		Description: "Allows reading file resource contents.",
	}
)

func init() {
	// Register permissions cleanly at startup (panics on duplicates to catch mistakes early)
	Registry.MustRegister(PermSystemCostView)
	Registry.MustRegister(PermTeamBillingRead)
	Registry.MustRegister(PermFileRead)
}
```

---

## Step 2: Assign Permissions to Built-In & Custom Roles

To ensure that pre-defined system roles (e.g., admin, authenticated user) or custom application roles hold these permissions, register and seed them idempotently during application bootstrapping.

### 2.1 Seed Built-In Role Grants
Configure and register grants dynamically at startup:

```go
package bootstrap

import (
	"context"
	"log"

	"auth"
	"github.com/wtiger001/go-permissions"
)

func SeedBuiltInRoles(ctx context.Context, svc *permissions.Service) error {
	builtInGrants := []permissions.Grant{
		// 1. Grant the global cost report permission to the synthetic Admin role
		{
			OwnerKind:      permissions.PrincipalRole,
			OwnerID:        permissions.SyntheticRoleAdmin,
			Effect:         permissions.EffectAllow,
			TeamScope:      "*",
			PermissionName: auth.PermSystemCostView.ID,
		},
		// 2. Grant team billing read permission dynamically using ?team template
		{
			OwnerKind:      permissions.PrincipalRole,
			OwnerID:        "role.team-member",
			Effect:         permissions.EffectAllow,
			TeamScope:      "?team",
			PermissionName: auth.PermTeamBillingRead.ID,
			VariableSpec:   map[string]any{"team": "required"},
		},
	}

	// Idempotently saves the grants at startup without duplicating existing entries
	if err := svc.EnsureGrantsForOwners(ctx, builtInGrants); err != nil {
		return err
	}

	log.Println("Successfully seeded built-in permission grants.")
	return nil
}
```

### 2.2 Create and Persist Custom Roles
If your application allows creating dynamic or custom roles, instantiate them using `permissions.Role` and save them directly via the `PermissionStore`:

```go
package bootstrap

import (
	"context"
	"fmt"

	"github.com/wtiger001/go-permissions"
)

func RegisterCustomRole(ctx context.Context, store permissions.PermissionStore) error {
	// Define a custom team role that requires team parameter binding
	projectManagerRole := permissions.Role{
		ID:          "role.project-manager",
		Name:        "Project Manager",
		Description: "Allows full CRUD management of folder structures and files.",
		VariableSpec: map[string]any{
			"team": "required",
		},
	}

	// Persist the role definition in the repository (idempotently)
	existing, err := store.RoleDefinition(ctx, projectManagerRole.ID)
	if err == nil && existing.ID == projectManagerRole.ID {
		return nil // Already exists, skip
	}

	if err := store.CreateRole(ctx, projectManagerRole); err != nil {
		return fmt.Errorf("failed to create custom role: %w", err)
	}

	return nil
}
```

---

## Step 3: Make Appropriate Permission Checks (Endpoint Level)

### 💡 Best Practice: Implement Checks inside Endpoint Handlers
**Always perform permission checks directly inside your endpoint handler/service logic, NOT in global HTTP routing middlewares.**

*Why?* Global middlewares lack the necessary domain context. While a middleware knows *which* HTTP route was called, it does not have safe access to parsed resource identifiers (like the `fileID` or `teamID` nested inside the request body), leading to overly rigid or complex middleware setups. 

By checking permissions inside the endpoint handler, you have fully parsed, typed, and validated values ready to supply directly to `HasPermission`.

### 3.1 System Scoped Check
System checks require only the `UserID` and the `PermissionName`:

```go
func HandleViewSystemCosts(w http.ResponseWriter, r *http.Request, svc *permissions.Service) {
	userID := GetAuthenticatedUserID(r)

	// Verify global system permission
	allowed, err := svc.HasPermission(ctx, permissions.Request{
		UserID: userID,
		Perm:   "finops.system-cost-report.view",
	})
	if err != nil || !allowed {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Render report...
}
```

### 3.2 Team Scoped Check
Team checks restrict permission to a specific `TeamID` context:

```go
func HandleViewTeamBilling(w http.ResponseWriter, r *http.Request, svc *permissions.Service) {
	userID := GetAuthenticatedUserID(r)
	teamID := ParseTeamIDFromRoute(r) // e.g., 42

	// Verify team scope permission
	allowed, err := svc.HasPermission(ctx, permissions.Request{
		UserID: userID,
		TeamID: &teamID,
		Perm:   "billing.team-billing.read",
	})
	if err != nil || !allowed {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Render billing...
}
```

### 3.3 Object Scoped Check
Object checks restrict permission to a specific resource instance identifier:

```go
func HandleReadFile(w http.ResponseWriter, r *http.Request, svc *permissions.Service) {
	userID := GetAuthenticatedUserID(r)
	fileID := ParseFileIDFromRoute(r) // e.g., "file_uuid_abc_123"

	// Verify object scope permission
	allowed, err := svc.HasPermission(ctx, permissions.Request{
		UserID: userID,
		Object: fileID,
		Perm:   "folders.file.read",
	})
	if err != nil || !allowed {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Read file contents...
}
```
