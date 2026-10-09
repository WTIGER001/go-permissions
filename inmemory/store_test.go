package inmemory

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/wtiger001/go-permissions"
)

func TestListPrincipalsWithGrant_DenyOverridesAllow(t *testing.T) {
	store := NewStore()
	teamID := "42"
	anyObject := "*"

	store.AddGrants(
		permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectAllow, TeamScope: "42", PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalGroup, OwnerID: "g-1", Effect: permissions.EffectDeny, TeamScope: "42", ObjectScope: &anyObject, PermissionName: "billing.read"},
		permissions.Grant{OwnerKind: permissions.PrincipalRole, OwnerID: "r-1", Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "billing.read"},
	)

	hits, err := store.PrincipalsWithGrant(context.Background(), permissions.Request{
		TeamID: teamID,
		Object: "billing",
		Perm:   "billing.read",
	})
	if err != nil {
		t.Fatalf("PrincipalsWithGrant: %v", err)
	}

	got := make([]string, 0, len(hits))
	for _, hit := range hits {
		got = append(got, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(got)

	expected := []string{"role:r-1", "user:u-1"}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

func TestTeamRoleAssignments(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	team := permissions.PrincipalRef{Kind: permissions.PrincipalTeam, ID: "team-1"}

	if err := store.AssignRole(ctx, team, "role.team-reader", nil, map[string]any{"scope": "all"}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	assignments, err := store.RoleAssignmentsForPrincipal(ctx, team)
	if err != nil || len(assignments) != 1 {
		t.Fatalf("RoleAssignmentsForPrincipal: assignments=%+v, err=%v", assignments, err)
	}
	hits, err := store.RoleAssignmentsForRoleID(ctx, "role.team-reader")
	if err != nil || len(hits) != 1 || hits[0].Kind != permissions.PrincipalTeam {
		t.Fatalf("RoleAssignmentsForRoleID: hits=%+v, err=%v", hits, err)
	}
	if err := store.UnassignRole(ctx, team, "role.team-reader", nil, map[string]any{"scope": "all"}); err != nil {
		t.Fatalf("UnassignRole: %v", err)
	}
}

func TestTeamRoleAssignmentsAuthorizeDirectAndGroupDerivedMembers(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	identity := NewIdentityProvider()
	identity.TeamMembership = map[string][]Entry{
		"team-direct": {{ID: "user-direct", Kind: UserMemberKind}},
		"team-group":  {{ID: "group-1", Kind: GroupMemberKind}},
	}
	identity.AddUserGroups("user-group", "group-1")

	for _, teamID := range []string{"team-direct", "team-group"} {
		if err := store.AssignRole(ctx, permissions.PrincipalRef{Kind: permissions.PrincipalTeam, ID: teamID}, "role.team-reader", nil, nil); err != nil {
			t.Fatalf("AssignRole(%s): %v", teamID, err)
		}
	}
	store.AddGrants(permissions.Grant{
		OwnerKind:      permissions.PrincipalRole,
		OwnerID:        "role.team-reader",
		Effect:         permissions.EffectAllow,
		TeamScope:      "*",
		PermissionName: "documents.read",
	})

	svc := permissions.NewService(store, identity)
	for _, userID := range []string{"user-direct", "user-group"} {
		allowed, err := svc.HasPermission(ctx, permissions.Request{UserID: userID, Perm: "documents.read"})
		if err != nil || !allowed {
			t.Fatalf("HasPermission(%s): allowed=%v, err=%v", userID, allowed, err)
		}
		effective, err := svc.EffectivePermissions(ctx, userID, "", "")
		if err != nil || len(effective) != 1 || effective[0].PermissionName != "documents.read" {
			t.Fatalf("EffectivePermissions(%s): permissions=%+v, err=%v", userID, effective, err)
		}
	}
}
