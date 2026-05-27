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

	perm := permissions.NewObjectPermission("datasets.view", "Data", "View Dataset", "Allows viewing datasets by region.", true).WithChecker(svc)

	shared.Must(svc.AllowUser(ctx, "analyst-global", perm.ID(), nil))
	shared.Must(svc.DenyUser(ctx, "analyst-global", perm.ID(), shared.StrPtr("region-restricted")))

	shared.PrintObjectCheck(ctx, svc, "analyst-global", "region-us", perm.ID(), "analyst-global can view region-us")
	shared.PrintObjectCheck(ctx, svc, "analyst-global", "region-eu", perm.ID(), "analyst-global can view region-eu")
	shared.PrintObjectCheck(ctx, svc, "analyst-global", "region-restricted", perm.ID(), "analyst-global can view region-restricted")
}
