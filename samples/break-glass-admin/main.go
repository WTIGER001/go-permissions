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

	perm := permissions.NewObjectPermission("incidents.resolve", "Incidents", "Resolve Incident", "Allows resolving incidents.").WithChecker(svc)

	if err := svc.AllowRole(ctx, "role.break_glass", perm.ID(), nil); err != nil {
		panic(err)
	}
	if err := svc.AssignRoleToUser(ctx, "oncall-admin", "role.break_glass", nil); err != nil {
		panic(err)
	}
	incident42 := "incident-42"
	if err := svc.DenyUser(ctx, "oncall-admin", perm.ID(), &incident42); err != nil {
		panic(err)
	}

	if perm.Can(ctx, "oncall-admin", "incident-41") {
		fmt.Print("oncall-admin can resolve incident-41\n")
	}

	if !perm.Can(ctx, "oncall-admin", "incident-42") {
		fmt.Print("oncall-admin cannot resolve incident-42\n")
	}
}
