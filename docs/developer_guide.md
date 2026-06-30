# Developer Implementation Guide: Authorization with `go-permissions`

This guide outlines how developers implement permission checks, register built-in roles, and perform authorization inside Go application services.

---

## 3-Step Implementation Workflow

To enforce authorization for any feature, follow this simple 3-step workflow:
1. **Create and Register Permissions:** Define what action is being authorized.
2. **Assign Permissions to Built-In & Custom Roles:** Register built-in feature roles in memory.
3. **Make Permission Checks:** Enforce checks inside endpoint implementations via `permissions.Service`.

---

## Step 1: Create and Register Permissions

Permissions are defined under a specific **Scope** and **Namespace** to keep them structured and fast to query.

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
)

func init() {
	Registry.MustRegister(PermSystemCostView)
	Registry.MustRegister(PermTeamBillingRead)
}
```

---

## Step 2: Register Built-In & Custom Roles via Service Proxy

Clients interact exclusively with `permissions.Service` rather than accessing the underlying store directly.

### 2.1 Add Built-In Feature Roles
Built-in feature role IDs **must begin with the prefix `builtin.`**. They are stored in memory and require no SQL seeding:

```go
package bootstrap

import (
	"context"
	"github.com/wtiger001/go-permissions"
)

func SeedBuiltInRoles(ctx context.Context, svc *permissions.Service) error {
	// Register a built-in role directly in memory
	err := svc.AddBuiltInRole(ctx, permissions.Role{
		ID:          "builtin.finops-viewer",
		Name:        "FinOps Viewer",
		Description: "Allows viewing financial reports",
		Permissions: []string{"finops.system-cost-report.view"},
	})
	if err != nil {
		return err
	}

	// Wire to synthetic admin role via in-memory inheritance
	return svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAdmin, "builtin.finops-viewer")
}
```

### 2.2 Create Custom Roles
Custom roles created at runtime via `svc.CreateRole` (without the `builtin.` prefix) are persisted in PostgreSQL:

```go
func CreateCustomRole(ctx context.Context, svc *permissions.Service) error {
	projectManagerRole := permissions.Role{
		ID:          "role.project-manager",
		Name:        "Project Manager",
		Description: "Custom project manager role",
	}

	return svc.CreateRole(ctx, projectManagerRole)
}
```

---

## Step 3: Make Permission Checks (Endpoint Level)

**Always perform permission checks directly inside endpoint handlers using `svc.HasPermission`.**

```go
func HandleViewSystemCosts(w http.ResponseWriter, r *http.Request, svc *permissions.Service) {
	userID := GetAuthenticatedUserID(r)

	// Verify global system permission
	allowed, err := svc.HasPermission(r.Context(), permissions.Request{
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
