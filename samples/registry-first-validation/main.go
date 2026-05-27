package main

import (
	"context"
	"fmt"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewServiceWithProviders(store, identity)

	registry := permissions.NewPermissionRegistry()
	validPerm := permissions.NewSystemPermission(
		"finops.system.report.view",
		"FinOps",
		"View System Report",
		"Allows viewing system-wide FinOps reporting.",
	).WithChecker(svc)

	fmt.Println("attempt invalid grant")
	if err := allowUserWithRegistry(ctx, svc, registry, "ops-user", "finops.system.typo", nil); err != nil {
		fmt.Printf("expected error: %v\n", err)
	}

	fmt.Println("register valid permission and retry")
	registry.MustRegister(validPerm.Definition())
	if err := allowUserWithRegistry(ctx, svc, registry, "ops-user", validPerm.ID(), nil); err != nil {
		fmt.Printf("grant error: %v\n", err)
		return
	}

	ok := validPerm.Can(ctx, "ops-user")

	fmt.Printf("ops-user has %s: %t\n", validPerm.ID(), ok)
}

func allowUserWithRegistry(ctx context.Context, svc *permissions.Service, registry *permissions.PermissionRegistry, userID, permission string, objectID *string) error {
	if !registry.Exists(permission) {
		return fmt.Errorf("permission %q is not registered", permission)
	}
	return svc.AllowUser(ctx, userID, permission, objectID)
}
