package main

import (
	"context"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
	"github.com/wtiger001/go-permissions/samples/shared"
)

func main() {
	ctx := context.Background()
	store := inmemory.NewStore()
	svc := permissions.NewService(store)

	perm := permissions.NewObjectPermission("groups.members.manage", "Groups", "Manage Members", "Allows managing members for one group.", true).WithChecker(svc)
	shared.Must(svc.AllowUser(ctx, "lead-1", perm.ID(), shared.StrPtr("group-a")))

	shared.PrintObjectCheck(ctx, svc, "lead-1", "group-a", perm.ID(), "lead-1 can manage group-a")
	shared.PrintObjectCheck(ctx, svc, "lead-1", "group-b", perm.ID(), "lead-1 can manage group-b")
}
