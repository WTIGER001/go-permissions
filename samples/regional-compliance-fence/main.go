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

	perm := permissions.NewObjectPermission("datasets.view", "Data", "View Dataset", "Allows viewing datasets by region.").WithChecker(svc)

	if err := svc.AllowUser(ctx, "analyst-global", perm.ID(), nil); err != nil {
		panic(err)
	}
	restricted := "region-restricted"
	if err := svc.DenyUser(ctx, "analyst-global", perm.ID(), &restricted); err != nil {
		panic(err)
	}

	for _, objectID := range []string{"region-us", "region-eu", "region-restricted"} {
		ok := perm.Can(ctx, "analyst-global", objectID)
		label := fmt.Sprintf("analyst-global can view %s", objectID)
		fmt.Printf("%s: %t\n", label, ok)
	}
}
