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
	s.grants = []permissions.Grant{}
	s.IdentityProvider.userGroups = map[string][]string{}
}

func (s *harnessStore) SeedDenyOverridesAllow(_ context.Context, _ *testing.T) permissions.Request {
	s.IdentityProvider.AddUserGroups("u-1", "g-1")
	s.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectDeny, TeamScope: "42", ObjectScope: strPtr("*"), PermissionName: "billing.read"},
	)

	teamID := int64(42)
	return permissions.Request{UserID: "u-1", TeamID: &teamID, Object: "billing", Perm: "billing.read"}
}

func (s *harnessStore) SeedStrictBindingError(_ context.Context, _ *testing.T) permissions.Request {
	s.AddUserRoleAssignments("u-1", permissions.RoleAssignment{RoleID: "r-parent", BindingValues: map[string]any{"team": 42}})
	s.SetRoleExpansion("r-parent", "r-child")
	s.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "r-child",
		Effect:         permissions.EffectAllow,
		TeamScope:      "*",
		PermissionName: "billing.read",
		VariableSpec:   map[string]any{"team": "required"},
	})

	teamID := int64(42)
	return permissions.Request{UserID: "u-1", TeamID: &teamID, Object: "billing", Perm: "billing.read"}
}

func (s *harnessStore) SeedEffectivePermissions(_ context.Context, _ *testing.T) testingharness.EffectiveExpectation {
	s.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "7", PermissionName: "report.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectDeny, TeamScope: "7", PermissionName: "report.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "7", PermissionName: "report.write"},
	)

	teamID := int64(7)
	return testingharness.EffectiveExpectation{
		UserID:          "u-1",
		TeamID:          &teamID,
		ExpectedPerms:   []string{"report.write"},
		UnexpectedPerms: []string{"report.read"},
	}
}

func strPtr(v string) *string {
	return &v
}
