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

	perm := permissions.NewObjectPermission("incidents.resolve", "Incidents", "Resolve Incident", "Allows resolving incidents.", true).WithChecker(svc)

	shared.Must(svc.AllowRole(ctx, "role.break_glass", perm.ID(), nil))
	shared.Must(svc.AssignRoleToUser(ctx, "oncall-admin", "role.break_glass", nil))
	shared.Must(svc.DenyUser(ctx, "oncall-admin", perm.ID(), shared.StrPtr("incident-42")))

	shared.PrintObjectCheck(ctx, svc, "oncall-admin", "incident-41", perm.ID(), "oncall-admin can resolve incident-41")
	shared.PrintObjectCheck(ctx, svc, "oncall-admin", "incident-42", perm.ID(), "oncall-admin can resolve incident-42")
}
