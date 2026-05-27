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

	perm := permissions.NewObjectPermission("groups.members.manage", "Groups", "Manage Members", "Allows managing members for one group.").WithChecker(svc)
	groupA := "group-a"
	if err := svc.AllowUser(ctx, "lead-1", perm.ID(), &groupA); err != nil {
		panic(err)
	}

	okA := perm.Can(ctx, "lead-1", "group-a")
	fmt.Printf("lead-1 can manage group-a: %t\n", okA)

	okB := perm.Can(ctx, "lead-1", "group-b")
	fmt.Printf("lead-1 can manage group-b: %t\n", okB)
}
