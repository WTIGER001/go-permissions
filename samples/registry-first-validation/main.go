package main

import (
	"context"
	"fmt"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
	"github.com/wtiger001/go-permissions/samples/shared"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	svc := permissions.NewService(store)

	registry := permissions.NewPermissionRegistry()
	validPerm := permissions.NewSystemPermission(
		"finops.system.report.view",
		"FinOps",
		"View System Report",
		"Allows viewing system-wide FinOps reporting.",
		true,
	)

	fmt.Println("attempt invalid grant")
	if err := allowUserWithRegistry(ctx, svc, registry, "ops-user", "finops.system.typo", nil); err != nil {
		fmt.Printf("expected error: %v\n", err)
	}

	fmt.Println("register valid permission and retry")
	registry.MustRegister(validPerm.Definition())
	shared.Must(allowUserWithRegistry(ctx, svc, registry, "ops-user", validPerm.ID(), nil))

	ok, err := svc.HasSystemPermission(ctx, "ops-user", validPerm.ID())
	if err != nil {
		fmt.Printf("check error: %v\n", err)
		return
	}
	fmt.Printf("ops-user has %s: %t\n", validPerm.ID(), ok)
}

func allowUserWithRegistry(ctx context.Context, svc *permissions.Service, registry *permissions.PermissionRegistry, userID, permission string, objectID *string) error {
	if !registry.Exists(permission) {
		return fmt.Errorf("permission %q is not registered", permission)
	}
	return svc.AllowUser(ctx, userID, permission, objectID)
}
