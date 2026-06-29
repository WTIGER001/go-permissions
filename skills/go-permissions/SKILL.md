---
name: go-permissions
description: Comprehensive guidance for integrating and using the go-permissions Go authorization library. Trigger when implementing authorization, writing permission checks, registering built-in or custom roles, wiring synthetic roles, or connecting identity providers in Go applications.
---

# Go-Permissions Skill Guide

This skill guides AI assistants in correctly implementing authorization workflows with `github.com/wtiger001/go-permissions`.

## When to Activate
Activate this skill whenever the user asks to:
- Implement authorization or permission checks in a Go application.
- Define or register built-in roles, custom roles, or role inheritance.
- Configure synthetic root roles (`builtin.public`, `builtin.authenticated`, `builtin.admin`).
- Implement a `permissions.IdentityProvider` adapter.

---

## Strict Implementation Rules

1. **Role ID Prefix Constraint**:
   All built-in roles MUST be prefixed with `builtin.` (e.g., `builtin.backup-operator`, `builtin.team-member`). Custom database roles created by users at runtime must NOT use the `builtin.` prefix.

2. **Service Encapsulation**:
   Clients interact exclusively with `*permissions.Service`. Never call or look for store interface methods directly. Use `svc.RoleDefinitions`, `svc.RoleDefinition`, `svc.CreateRole`, `svc.AddRoleInheritance`, `svc.DisableBuiltInRole`, and `svc.EnableBuiltInRole`.

3. **Synthetic Role Wiring**:
   Synthetic roles (`builtin.public`, `builtin.authenticated`, `builtin.admin`) are evaluated dynamically. Wire feature roles to synthetic roles using `svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAdmin, "builtin.feature-role")`. Configure the admin trigger group using `svc.SetAdminGroupID("group.admins")`.

4. **Endpoint Level Authorization**:
   Always perform `svc.HasPermission(ctx, req)` directly inside API handlers/service functions where request parameters (`TeamID`, `Object`, `UserID`) are cleanly parsed. Avoid generic HTTP routing middlewares for permission enforcement.

---

## Canonical Patterns

### 1. Identity Adapter Implementation
```go
type ApplicationIdentityProvider struct {
    GroupManager MyGroupManager
}

func (p ApplicationIdentityProvider) GetUserGroups(ctx context.Context, userID string) ([]string, error) {
    return p.GroupManager.FetchGroupIDsForUser(ctx, userID)
}
func (p ApplicationIdentityProvider) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) {
    return p.GroupManager.FetchUserIDsInGroup(ctx, groupID)
}
func (p ApplicationIdentityProvider) IsUserInGroup(ctx context.Context, userID, groupID string) (bool, error) {
    groups, err := p.GetUserGroups(ctx, userID)
    if err != nil { return false, err }
    for _, g := range groups { if g == groupID { return true, nil } }
    return false, nil
}
```

### 2. Startup Bootstrap Sequence
```go
svc := permissions.NewServiceWithIdentity(identityAdapter, postgresStore)
svc.SetAdminGroupID("group.admins")

// Register built-in feature role
svc.BootstrapBuiltInRole(ctx, permissions.Role{
    ID:          "builtin.backup-operator",
    Name:        "Backup Operator",
    Permissions: []string{"backup.run", "backup.list"},
})

// Wire built-in feature role to synthetic admin role
svc.AddRoleInheritance(ctx, permissions.SyntheticRoleAdmin, "builtin.backup-operator")
```

### 3. Permission Check Pattern
```go
allowed, err := svc.HasPermission(ctx, permissions.Request{
    UserID: userID, // "" for anonymous, user ID string for authenticated
    TeamID: teamID, // Optional pointer to team ID
    Object: objectID, // Optional object resource string
    Perm:   "backup.run",
})
```
