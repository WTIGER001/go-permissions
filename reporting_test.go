package permissions_test

import (
	"context"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func setupReportingTest(t *testing.T) (*permissions.Service, context.Context) {
	svc := permissions.New()
	ctx := context.Background()

	// Seed some roles
	_ = svc.CreateRole(ctx, permissions.Role{
		ID:          "role.admin",
		Name:        "Admin",
		Permissions: []string{"system.admin"},
	})
	_ = svc.CreateRole(ctx, permissions.Role{
		ID:          "role.vm_viewer",
		Name:        "VM Viewer",
		Permissions: []string{"vms.virtualmachine.read", "vms.virtualmachine.list"},
	})
	_ = svc.CreateRole(ctx, permissions.Role{
		ID:          "role.vm_admin",
		Name:        "VM Admin",
		Permissions: []string{"vms.virtualmachine.create", "vms.virtualmachine.delete"},
	})
	_ = svc.AddRoleInheritance(ctx, "role.vm_admin", "role.vm_viewer")

	// Seed some direct grants
	// System level grant (*)
	_ = svc.CreateGrant(ctx, permissions.Grant{
		OwnerKind:      permissions.PrincipalUser,
		OwnerID:        "u-sysadmin",
		TeamScope:      "*",
		PermissionName: "system.admin",
		Effect:         permissions.EffectAllow,
	})

	// Team level grants
	_ = svc.CreateGrant(ctx, permissions.Grant{
		OwnerKind:      permissions.PrincipalGroup,
		OwnerID:        "g-teamA-devs",
		TeamScope:      "teamA",
		PermissionName: "vms.virtualmachine.create",
		Effect:         permissions.EffectAllow,
	})
	_ = svc.CreateGrant(ctx, permissions.Grant{
		OwnerKind:      permissions.PrincipalUser,
		OwnerID:        "u-alice",
		TeamScope:      "teamA",
		PermissionName: "vms.virtualmachine.read",
		Effect:         permissions.EffectAllow,
	})

	// Assign roles (which creates effective permissions)
	_ = svc.AssignRole(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u-bob"}, "role.vm_admin", nil)
	_ = svc.AssignRole(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalGroup, ID: "g-viewers"}, "role.vm_viewer", nil)

	return svc, ctx
}

func TestGenerateReport_UseCase1_WhoHasAccessAndWhy(t *testing.T) {
	svc, ctx := setupReportingTest(t)

	// Bob is assigned role.vm_admin. We want to see his effective permissions.
	res, err := svc.GenerateReport(ctx, permissions.GrantQuery{
		Principals: []permissions.PrincipalRef{
			{Kind: permissions.PrincipalUser, ID: "u-bob"},
		},
		IncludeEffective: true,
	})
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	// Bob should have vms.virtualmachine.create, delete (from vm_admin), and read, list (from vm_viewer)
	if len(res.Reports) < 4 {
		t.Errorf("Expected at least 4 effective permission reports for bob, got %d", len(res.Reports))
	}

	foundCreate := false
	for _, r := range res.Reports {
		if r.PermissionName == "vms.virtualmachine.create" && r.Principal.ID == "u-bob" {
			foundCreate = true
			if r.IsDirect {
				t.Errorf("Expected role-based permission to be IsDirect=false")
			}
			if len(r.Sources) == 0 || r.Sources[0].Kind != permissions.PrincipalRole {
				t.Errorf("Expected source to be Role, got %v", r.Sources)
			}
		}
	}
	if !foundCreate {
		t.Errorf("Did not find effective permission vms.virtualmachine.create for bob")
	}
}

func TestGenerateReport_UseCase2_SystemLevelGrants(t *testing.T) {
	svc, ctx := setupReportingTest(t)

	res, err := svc.GenerateReport(ctx, permissions.GrantQuery{
		TeamScopes:       []string{"*"},
		IncludeEffective: false,
	})
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	if len(res.Reports) == 0 {
		t.Fatalf("Expected at least 1 system level grant report")
	}

	foundSysAdmin := false
	for _, r := range res.Reports {
		if r.TeamScope == "*" && r.PermissionName == "system.admin" {
			foundSysAdmin = true
		}
	}
	if !foundSysAdmin {
		t.Errorf("Did not find system.admin grant in report")
	}
}

func TestGenerateReport_UseCase3_TeamLevelGrants(t *testing.T) {
	svc, ctx := setupReportingTest(t)

	res, err := svc.GenerateReport(ctx, permissions.GrantQuery{
		TeamScopes:       []string{"teamA"},
		IncludeEffective: false,
	})
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	if len(res.Reports) != 2 {
		t.Errorf("Expected 2 direct grants for teamA, got %d", len(res.Reports))
	}

	for _, r := range res.Reports {
		if r.TeamScope != "teamA" {
			t.Errorf("Expected team scope teamA, got %s", r.TeamScope)
		}
	}
}

func TestGenerateReport_UseCase4_PatternMatching(t *testing.T) {
	svc, ctx := setupReportingTest(t)

	res, err := svc.GenerateReport(ctx, permissions.GrantQuery{
		PermissionPrefix: "vms.virtualmachine.",
		IncludeEffective: false,
	})
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	// Should match vms.virtualmachine.create and vms.virtualmachine.read
	if len(res.Reports) != 2 {
		t.Errorf("Expected 2 direct pattern matched grants, got %d", len(res.Reports))
	}

	for _, r := range res.Reports {
		if r.PermissionName != "vms.virtualmachine.create" && r.PermissionName != "vms.virtualmachine.read" {
			t.Errorf("Unexpected permission name %s", r.PermissionName)
		}
	}
}
