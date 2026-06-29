# AI Agent & LLM Coding Guidelines for `go-permissions`

This document provides explicit guidelines for AI coding assistants (Gemini, Claude, Cursor, GitHub Copilot, Antigravity) working with or integrating `github.com/wtiger001/go-permissions`.

---

## Core Architectural Rules for AI Assistants

When generating or modifying code that uses `go-permissions`, ALWAYS follow these fundamental constraints:

### 1. Mandatory Built-In Role Prefix
- **Rule**: All system built-in role IDs MUST begin with the prefix `builtin.` (e.g., `builtin.backup-operator`, `builtin.team-member`).
- **Incorrect**: `permissions.Role{ID: "role.backup-operator", ...}`
- **Correct**: `permissions.Role{ID: "builtin.backup-operator", ...}`

### 2. Client Interaction via `Service` Proxying Only
- **Rule**: Never attempt to access or invoke methods on the raw `PermissionStore` directly (do not look for a `.Store()` getter). Always call proxy methods directly on `*permissions.Service`.
- **Correct Methods on Service**:
  - `svc.RoleDefinitions(ctx)` (Combines in-memory built-ins and DB custom roles)
  - `svc.RoleDefinition(ctx, roleID)`
  - `svc.CreateRole(ctx, role)`
  - `svc.AddRoleInheritance(ctx, parentRoleID, childRoleID)`
  - `svc.DisableBuiltInRole(ctx, roleID)` / `svc.EnableBuiltInRole(ctx, roleID)`

### 3. Synthetic Roles & Authentication State
- Synthetic roles are evaluated automatically by `go-permissions` based on the request context:
  - `permissions.SyntheticRolePublic` (`"builtin.public"`): Automatically evaluated for all requests.
  - `permissions.SyntheticRoleAuthenticated` (`"builtin.authenticated"`): Automatically evaluated when `Request.UserID != ""`.
  - `permissions.SyntheticRoleAdmin` (`"builtin.admin"`): Automatically evaluated when `Request.UserID != ""` AND the user belongs to the group configured via `svc.SetAdminGroupID("group.admins")`.

### 4. Permission Check Placement
- **Rule**: Always perform permission checks directly inside endpoint handlers or business logic functions using `svc.HasPermission(...)`. Do NOT create global HTTP routing middlewares for permission checks, as middlewares lack parsed domain context (`TeamID`, `Object`).

---

## Quick Reference Code Snippets for AI

### Registering Built-In Roles at Application Startup
```go
func InitBuiltIns(ctx context.Context, svc *permissions.Service) error {
    // Register built-in feature role in memory
    err := svc.BootstrapBuiltInRole(ctx, permissions.Role{
        ID:          "builtin.backup-operator",
        Name:        "Backup Operator",
        Description: "Allows system backup operations",
        Permissions: []string{"backup.run", "backup.list"},
    })
    if err != nil {
        return err
    }

    // Wire feature role to synthetic admin role via in-memory inheritance
    return svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAdmin, "builtin.backup-operator")
}
```

### Checking Permissions in API Handlers
```go
func HandleRunBackup(w http.ResponseWriter, r *http.Request, svc *permissions.Service, currentUserID string) {
    allowed, err := svc.HasPermission(r.Context(), permissions.Request{
        UserID: currentUserID, // Pass "" for anonymous, user ID string for authenticated users
        Perm:   "backup.run",
    })
    if err != nil || !allowed {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Execution logic...
}
```
