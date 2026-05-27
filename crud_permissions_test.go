package permissions

import "testing"

func TestNewSystemCRUDPermissions(t *testing.T) {
	crud := NewSystemCRUDPermissions("blog.article")

	if crud.Create.ID() != "blog.article.create" {
		t.Fatalf("unexpected create ID %q", crud.Create.ID())
	}
	if crud.Read.ID() != "blog.article.read" {
		t.Fatalf("unexpected read ID %q", crud.Read.ID())
	}
	if crud.Update.ID() != "blog.article.update" {
		t.Fatalf("unexpected update ID %q", crud.Update.ID())
	}
	if crud.Delete.ID() != "blog.article.delete" {
		t.Fatalf("unexpected delete ID %q", crud.Delete.ID())
	}
	if crud.Grant.ID() != "blog.article.grant" {
		t.Fatalf("unexpected grant ID %q", crud.Grant.ID())
	}

	if crud.Create.Definition().Scope != PermissionScopeSystem {
		t.Fatalf("expected system scope, got %q", crud.Create.Definition().Scope)
	}
	if crud.Create.Namespace() != "Blog" {
		t.Fatalf("expected namespace Blog, got %q", crud.Create.Namespace())
	}
	if crud.Create.Name() != "Create Blog Article" {
		t.Fatalf("unexpected name %q", crud.Create.Name())
	}
}

func TestNewTeamCRUDPermissions(t *testing.T) {
	crud := NewTeamCRUDPermissions("billing.invoice")

	if crud.Create.ID() != "billing.invoice.create" {
		t.Fatalf("unexpected create ID %q", crud.Create.ID())
	}
	if crud.Read.ID() != "billing.invoice.read" {
		t.Fatalf("unexpected read ID %q", crud.Read.ID())
	}
	if crud.Update.ID() != "billing.invoice.update" {
		t.Fatalf("unexpected update ID %q", crud.Update.ID())
	}
	if crud.Delete.ID() != "billing.invoice.delete" {
		t.Fatalf("unexpected delete ID %q", crud.Delete.ID())
	}
	if crud.Grant.ID() != "billing.invoice.grant" {
		t.Fatalf("unexpected grant ID %q", crud.Grant.ID())
	}

	if crud.Read.Definition().Scope != PermissionScopeTeam {
		t.Fatalf("expected team scope, got %q", crud.Read.Definition().Scope)
	}
	if crud.Read.Namespace() != "Billing" {
		t.Fatalf("expected namespace Billing, got %q", crud.Read.Namespace())
	}
}

func TestNewCRUDPermissions_EmptyRootFallback(t *testing.T) {
	systemCRUD := NewSystemCRUDPermissions("   ")
	teamCRUD := NewTeamCRUDPermissions("...")

	if systemCRUD.Create.ID() != "resource.create" {
		t.Fatalf("unexpected fallback system create ID %q", systemCRUD.Create.ID())
	}
	if teamCRUD.Delete.ID() != "resource.delete" {
		t.Fatalf("unexpected fallback team delete ID %q", teamCRUD.Delete.ID())
	}
	if teamCRUD.Grant.ID() != "resource.grant" {
		t.Fatalf("unexpected fallback team grant ID %q", teamCRUD.Grant.ID())
	}
}

func TestNewCRUDPermissions_WithCustomNamespaceAndBuilders(t *testing.T) {
	options := CRUDPermissionOptions{
		Namespace:    "Content",
		ResourceName: "Blog Post",
		NameBuilder: func(action CRUDAction, resourceName string) string {
			return "Can " + humanizePermissionToken(string(action)) + " " + resourceName
		},
		DescriptionBuilder: func(action CRUDAction, resourceName string) string {
			return "Grant " + string(action) + " for " + resourceName
		},
	}

	crud := NewTeamCRUDPermissionsWithOptions("blog.article", options)

	if crud.Create.Namespace() != "Content" {
		t.Fatalf("expected namespace Content, got %q", crud.Create.Namespace())
	}
	if crud.Update.Name() != "Can Update Blog Post" {
		t.Fatalf("unexpected custom name %q", crud.Update.Name())
	}
	if crud.Delete.Description() != "Grant delete for Blog Post" {
		t.Fatalf("unexpected custom description %q", crud.Delete.Description())
	}
	if crud.Grant.Name() != "Can Grant Blog Post" {
		t.Fatalf("unexpected custom grant name %q", crud.Grant.Name())
	}
}

func TestPermissionSuffixGrantConstant(t *testing.T) {
	if PermissionSuffixGrant != "grant" {
		t.Fatalf("unexpected grant suffix constant %q", PermissionSuffixGrant)
	}
}
