package examples

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	permissions "github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/inmemory"
)

type customerProfile struct {
	ID        string
	Name      string
	Status    string
	Sensitive string
}

// TestFieldScopedSensitiveObject demonstrates two users reading the same object with different field visibility,
// and then applying writes where only permitted fields are updated.
func TestFieldScopedSensitiveObject(t *testing.T) {
	ctx := context.Background()
	store := inmemory.NewStore()
	identity := inmemory.NewIdentityProvider()
	svc := permissions.NewService(store, identity)

	teamID := int64(501)
	teamScope := strconv.FormatInt(teamID, 10)
	objectID := "customer-1"

	readPerm := permissions.NewObjectPermission("customer.read", "Customer", "Read Customer", "Allows reading customer profile fields.").WithChecker(svc)
	writePerm := permissions.NewObjectPermission("customer.write", "Customer", "Write Customer", "Allows writing customer profile fields.").WithChecker(svc)

	store.AddGrants(
		permissions.Grant{
			OwnerKind:        permissions.PrincipalUser,
			OwnerID:          "user-full",
			Effect:           permissions.EffectAllow,
			TeamScope:        teamScope,
			ObjectScope:      &objectID,
			PermissionName:   readPerm.ID(),
			RestrictedFields: nil,
		},
		permissions.Grant{
			OwnerKind:        permissions.PrincipalUser,
			OwnerID:          "user-basic",
			Effect:           permissions.EffectAllow,
			TeamScope:        teamScope,
			ObjectScope:      &objectID,
			PermissionName:   readPerm.ID(),
			RestrictedFields: []string{"sensitive"},
		},
		permissions.Grant{
			OwnerKind:        permissions.PrincipalUser,
			OwnerID:          "user-full",
			Effect:           permissions.EffectAllow,
			TeamScope:        teamScope,
			ObjectScope:      &objectID,
			PermissionName:   writePerm.ID(),
			RestrictedFields: nil,
		},
		permissions.Grant{
			OwnerKind:        permissions.PrincipalUser,
			OwnerID:          "user-basic",
			Effect:           permissions.EffectAllow,
			TeamScope:        teamScope,
			ObjectScope:      &objectID,
			PermissionName:   writePerm.ID(),
			RestrictedFields: []string{"sensitive"},
		},
	)

	allFields := []string{"id", "name", "status", "sensitive"}

	fullReadable, err := svc.FilterPermittedFields(ctx, permissions.Request{
		UserID: "user-full",
		TeamID: &teamID,
		Object: objectID,
		Perm:   readPerm.ID(),
	}, allFields)
	if err != nil {
		t.Fatalf("full read filter error: %v", err)
	}
	if !reflect.DeepEqual(fullReadable, allFields) {
		t.Fatalf("expected full user fields %v, got %v", allFields, fullReadable)
	}

	basicReadable, err := svc.FilterPermittedFields(ctx, permissions.Request{
		UserID: "user-basic",
		TeamID: &teamID,
		Object: objectID,
		Perm:   readPerm.ID(),
	}, allFields)
	if err != nil {
		t.Fatalf("basic read filter error: %v", err)
	}
	basicExpected := []string{"id", "name", "status"}
	if !reflect.DeepEqual(basicReadable, basicExpected) {
		t.Fatalf("expected basic user fields %v, got %v", basicExpected, basicReadable)
	}

	profile := customerProfile{ID: "customer-1", Name: "Alice", Status: "pending", Sensitive: "ssn:111-22-3333"}
	basicUpdates := map[string]string{"status": "approved", "sensitive": "redacted"}

	basicWritable, err := svc.FilterPermittedFields(ctx, permissions.Request{
		UserID: "user-basic",
		TeamID: &teamID,
		Object: objectID,
		Perm:   writePerm.ID(),
	}, []string{"status", "sensitive"})
	if err != nil {
		t.Fatalf("basic write filter error: %v", err)
	}

	for _, field := range basicWritable {
		switch field {
		case "status":
			profile.Status = basicUpdates[field]
		case "sensitive":
			profile.Sensitive = basicUpdates[field]
		}
	}

	if profile.Status != "approved" {
		t.Fatalf("expected status to be updated by basic user, got %q", profile.Status)
	}
	if profile.Sensitive != "ssn:111-22-3333" {
		t.Fatalf("expected sensitive value to remain unchanged for basic user, got %q", profile.Sensitive)
	}

	fullCanWriteSensitive, err := svc.HasFieldPermission(ctx, permissions.Request{
		UserID: "user-full",
		TeamID: &teamID,
		Object: objectID,
		Perm:   writePerm.ID(),
	}, "sensitive")
	if err != nil {
		t.Fatalf("full write sensitive check error: %v", err)
	}
	if !fullCanWriteSensitive {
		t.Fatalf("expected full user to be able to write sensitive field")
	}
}
