package inmemory

import (
	"context"
	"testing"

	"github.com/wtiger001/go-permissions"
	"github.com/wtiger001/go-permissions/testingharness"
)

type harnessStore struct {
	*Store
	*IdentityProvider
}

func TestInMemoryServiceContractSuite(t *testing.T) {
	h := testingharness.NewHarness(&harnessStore{Store: NewStore(), IdentityProvider: NewIdentityProvider()})
	h.RunAll(t)
}

func (s *harnessStore) HarnessName() string {
	return "inmemory"
}

func (s *harnessStore) Reset(_ context.Context, _ *testing.T) {
	s.userRoleAssignments = map[string][]permissions.RoleAssignment{}
	s.groupRoleAssignments = map[string][]permissions.RoleAssignment{}
	s.roleExpansion = map[string][]string{}
	s.roleInheritance = map[string]map[string]bool{}
	s.roleClosure = map[string]map[string]bool{}
	s.grants = []permissions.Grant{}
	s.TeamMembership = map[string][]Entry{}
	s.IdentityProvider.userGroups = map[string][]string{}
}

func (s *harnessStore) SeedDenyOverridesAllow(_ context.Context, _ *testing.T) permissions.Request {
	s.IdentityProvider.AddUserGroups("u-1", "g-1")
	s.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectDeny, TeamScope: "42", ObjectScope: strPtr("*"), PermissionName: "billing.read"},
	)

	teamID := "42"
	return permissions.Request{UserID: "u-1", TeamID: teamID, Object: "billing", Perm: "billing.read"}
}

func (s *harnessStore) SeedStrictBindingError(_ context.Context, _ *testing.T) permissions.Request {
	s.AddUserRoleAssignments("u-1", permissions.RoleAssignment{RoleID: "r-parent", BindingValues: map[string]any{"team": 42}})
	s.TeamMembership = map[string][]Entry{
		"42": {
			Entry{
				ID:   "u-1",
				Kind: UserMemberKind,
			},
		},
	}
	s.SetRoleExpansion("r-parent", "r-child")
	s.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "r-child",
		Effect:         permissions.EffectAllow,
		TeamScope:      "*",
		PermissionName: "billing.read",
		VariableSpec:   map[string]any{"team": "required"},
	})

	teamID := "42"
	return permissions.Request{UserID: "u-1", TeamID: teamID, Object: "billing", Perm: "billing.read"}
}

func (s *harnessStore) SeedEffectivePermissions(_ context.Context, _ *testing.T) testingharness.EffectiveExpectation {
	s.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "7", PermissionName: "report.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectDeny, TeamScope: "7", PermissionName: "report.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "7", PermissionName: "report.write"},
	)

	s.TeamMembership = map[string][]Entry{
		"7": {
			{
				ID:   "u-1",
				Kind: UserMemberKind,
			},
		},
	}

	teamID := "7"
	return testingharness.EffectiveExpectation{
		UserID:          "u-1",
		TeamID:          teamID,
		ExpectedPerms:   []string{"report.write"},
		UnexpectedPerms: []string{"report.read"},
	}
}

func (s *harnessStore) SeedTransitiveRoles(ctx context.Context, t *testing.T) permissions.Request {
	t.Helper()
	// Build: user u-1 -> r-top -> r-mid -> r-leaf (3-hop chain).
	// Grant is only on r-leaf; the service must expand the chain to find it.
	if err := s.AddRoleInheritance(ctx, "r-top", "r-mid"); err != nil {
		t.Fatalf("AddRoleInheritance r-top->r-mid: %v", err)
	}
	if err := s.AddRoleInheritance(ctx, "r-mid", "r-leaf"); err != nil {
		t.Fatalf("AddRoleInheritance r-mid->r-leaf: %v", err)
	}
	s.AddUserRoleAssignments("u-1", permissions.RoleAssignment{RoleID: "r-top", BindingValues: map[string]any{}})
	s.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "r-leaf",
		Effect:         permissions.EffectAllow,
		TeamScope:      "*",
		PermissionName: "reports.view",
	})
	return permissions.Request{UserID: "u-1", TeamID: "", Object: "reports", Perm: "reports.view"}
}

func strPtr(v string) *string {
	return &v
}
