package cachedstore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/wtiger001/go-permissions"
)

type countingStore struct {
	mu                       sync.Mutex
	roleDefinitionsCalls     int
	roleDefinitionCalls      int
	roleAssignmentsCalls     int
	grantsForPrincipalCalls  int
	expandRolesCalls         int
	grantsForOwnersCalls     int
	principalsWithGrantCalls int
	roleAssignWriteCalls     int
	grantWriteCalls          int
	createRoleCalls          int
	updateRoleCalls          int
	deleteRoleCalls          int
}

func (s *countingStore) RoleDefinitions(_ context.Context) ([]permissions.Role, error) {
	s.mu.Lock()
	s.roleDefinitionsCalls++
	s.mu.Unlock()
	return []permissions.Role{{ID: "r-1", Name: "role-1"}}, nil
}

func (s *countingStore) RoleDefinition(_ context.Context, roleID string) (permissions.Role, error) {
	s.mu.Lock()
	s.roleDefinitionCalls++
	s.mu.Unlock()
	return permissions.Role{ID: roleID, Name: roleID}, nil
}

func (s *countingStore) RoleAssignmentsForPrincipal(_ context.Context, _ permissions.PrincipalRef) ([]permissions.RoleAssignment, error) {
	s.mu.Lock()
	s.roleAssignmentsCalls++
	s.mu.Unlock()
	return []permissions.RoleAssignment{{RoleID: "r-1", BindingValues: map[string]any{"team": 42}}}, nil
}

func (s *countingStore) GrantsForPrincipal(_ context.Context, principal permissions.PrincipalRef) ([]permissions.Grant, error) {
	s.mu.Lock()
	s.grantsForPrincipalCalls++
	s.mu.Unlock()
	return []permissions.Grant{{OwnerKind: principal.Kind, OwnerID: principal.ID, Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "p.read"}}, nil
}

func (s *countingStore) ExpandRoles(_ context.Context, roleIDs []string) ([]string, error) {
	s.mu.Lock()
	s.expandRolesCalls++
	s.mu.Unlock()
	return append([]string(nil), roleIDs...), nil
}

func (s *countingStore) GrantsForOwners(_ context.Context, _ []permissions.PrincipalRef, _ permissions.Request) ([]permissions.Grant, error) {
	s.mu.Lock()
	s.grantsForOwnersCalls++
	s.mu.Unlock()
	return []permissions.Grant{{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "p.read"}}, nil
}

func (s *countingStore) PrincipalsWithGrant(_ context.Context, _ permissions.Request) ([]permissions.PrincipalHit, error) {
	s.mu.Lock()
	s.principalsWithGrantCalls++
	s.mu.Unlock()
	return []permissions.PrincipalHit{{Kind: permissions.PrincipalUser, ID: "u-1", TeamScope: "*", PermissionName: "p.read"}}, nil
}

func (s *countingStore) CreateGrant(_ context.Context, _ permissions.Grant) error {
	s.mu.Lock()
	s.grantWriteCalls++
	s.mu.Unlock()
	return nil
}

func (s *countingStore) AssignRole(_ context.Context, _ permissions.PrincipalRef, _ string, _ map[string]any) error {
	s.mu.Lock()
	s.roleAssignWriteCalls++
	s.mu.Unlock()
	return nil
}

func (s *countingStore) CreateRole(_ context.Context, _ permissions.Role) error {
	s.mu.Lock()
	s.createRoleCalls++
	s.mu.Unlock()
	return nil
}

func (s *countingStore) UpdateRole(_ context.Context, _ permissions.Role) error {
	s.mu.Lock()
	s.updateRoleCalls++
	s.mu.Unlock()
	return nil
}

func (s *countingStore) DeleteRole(_ context.Context, _ string) error {
	s.mu.Lock()
	s.deleteRoleCalls++
	s.mu.Unlock()
	return nil
}

func TestStore_CachesReadResults(t *testing.T) {
	base := &countingStore{}
	store := NewStoreWithTTL(base, time.Minute)
	ctx := context.Background()

	principal := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u-1"}
	owners := []permissions.PrincipalRef{{Kind: permissions.PrincipalUser, ID: "u-1"}}
	req := permissions.Request{UserID: "u-1", Perm: "p.read"}

	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("first role definitions failed: %v", err)
	}
	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("second role definitions failed: %v", err)
	}

	if _, err := store.RoleDefinition(ctx, "r-1"); err != nil {
		t.Fatalf("first role definition failed: %v", err)
	}
	if _, err := store.RoleDefinition(ctx, "r-1"); err != nil {
		t.Fatalf("second role definition failed: %v", err)
	}

	if _, err := store.RoleAssignmentsForPrincipal(ctx, principal); err != nil {
		t.Fatalf("first role assignments failed: %v", err)
	}
	if _, err := store.RoleAssignmentsForPrincipal(ctx, principal); err != nil {
		t.Fatalf("second role assignments failed: %v", err)
	}

	if _, err := store.GrantsForPrincipal(ctx, principal); err != nil {
		t.Fatalf("first grants-for-principal failed: %v", err)
	}
	if _, err := store.GrantsForPrincipal(ctx, principal); err != nil {
		t.Fatalf("second grants-for-principal failed: %v", err)
	}

	if _, err := store.ExpandRoles(ctx, []string{"r-1"}); err != nil {
		t.Fatalf("first expand-roles failed: %v", err)
	}
	if _, err := store.ExpandRoles(ctx, []string{"r-1"}); err != nil {
		t.Fatalf("second expand-roles failed: %v", err)
	}

	if _, err := store.GrantsForOwners(ctx, owners, req); err != nil {
		t.Fatalf("first grants-for-owners failed: %v", err)
	}
	if _, err := store.GrantsForOwners(ctx, owners, req); err != nil {
		t.Fatalf("second grants-for-owners failed: %v", err)
	}

	if _, err := store.PrincipalsWithGrant(ctx, req); err != nil {
		t.Fatalf("first principals-with-grant failed: %v", err)
	}
	if _, err := store.PrincipalsWithGrant(ctx, req); err != nil {
		t.Fatalf("second principals-with-grant failed: %v", err)
	}

	if base.roleDefinitionsCalls != 1 {
		t.Fatalf("expected 1 role-definitions call, got %d", base.roleDefinitionsCalls)
	}
	if base.roleDefinitionCalls != 1 {
		t.Fatalf("expected 1 role-definition call, got %d", base.roleDefinitionCalls)
	}
	if base.roleAssignmentsCalls != 1 {
		t.Fatalf("expected 1 role-assignments call, got %d", base.roleAssignmentsCalls)
	}
	if base.grantsForPrincipalCalls != 1 {
		t.Fatalf("expected 1 grants-for-principal call, got %d", base.grantsForPrincipalCalls)
	}
	if base.expandRolesCalls != 1 {
		t.Fatalf("expected 1 expand-roles call, got %d", base.expandRolesCalls)
	}
	if base.grantsForOwnersCalls != 1 {
		t.Fatalf("expected 1 grants-for-owners call, got %d", base.grantsForOwnersCalls)
	}
	if base.principalsWithGrantCalls != 1 {
		t.Fatalf("expected 1 principals-with-grant call, got %d", base.principalsWithGrantCalls)
	}
}

func TestStore_InvalidateOnWrites(t *testing.T) {
	base := &countingStore{}
	store := NewStoreWithTTL(base, time.Minute)
	ctx := context.Background()

	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("prime cache failed: %v", err)
	}
	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("cache hit failed: %v", err)
	}

	if err := store.CreateGrant(ctx, permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "p.read"}); err != nil {
		t.Fatalf("create grant failed: %v", err)
	}

	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("post-invalidation read failed: %v", err)
	}

	if base.grantWriteCalls != 1 {
		t.Fatalf("expected 1 grant write call, got %d", base.grantWriteCalls)
	}
	if base.roleDefinitionsCalls != 2 {
		t.Fatalf("expected cache flush to force second backend read, got %d calls", base.roleDefinitionsCalls)
	}
}

func TestStore_TTLExpiry(t *testing.T) {
	base := &countingStore{}
	store := NewStoreWithTTL(base, 30*time.Millisecond)
	ctx := context.Background()
	principal := permissions.PrincipalRef{Kind: permissions.PrincipalUser, ID: "u-1"}

	if _, err := store.RoleAssignmentsForPrincipal(ctx, principal); err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if _, err := store.RoleAssignmentsForPrincipal(ctx, principal); err != nil {
		t.Fatalf("cached read failed: %v", err)
	}
	if base.roleAssignmentsCalls != 1 {
		t.Fatalf("expected 1 backend call before TTL expiry, got %d", base.roleAssignmentsCalls)
	}

	time.Sleep(50 * time.Millisecond)
	if _, err := store.RoleAssignmentsForPrincipal(ctx, principal); err != nil {
		t.Fatalf("post-expiry read failed: %v", err)
	}
	if base.roleAssignmentsCalls != 2 {
		t.Fatalf("expected backend call after TTL expiry, got %d", base.roleAssignmentsCalls)
	}
}

func TestStore_NewStoreDefaultTTL(t *testing.T) {
	base := &countingStore{}
	store := NewStore(base)
	if store.TTL() != DefaultTTL {
		t.Fatalf("expected default TTL %v, got %v", DefaultTTL, store.TTL())
	}
}

func TestStore_RoleWritesInvalidateCache(t *testing.T) {
	base := &countingStore{}
	store := NewStoreWithTTL(base, time.Minute)
	ctx := context.Background()

	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("prime cache failed: %v", err)
	}
	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("cache hit failed: %v", err)
	}

	if err := store.CreateRole(ctx, permissions.Role{ID: "r-2", Name: "role-2"}); err != nil {
		t.Fatalf("create role failed: %v", err)
	}
	if err := store.UpdateRole(ctx, permissions.Role{ID: "r-2", Name: "role-2"}); err != nil {
		t.Fatalf("update role failed: %v", err)
	}
	if err := store.DeleteRole(ctx, "r-2"); err != nil {
		t.Fatalf("delete role failed: %v", err)
	}

	if _, err := store.RoleDefinitions(ctx); err != nil {
		t.Fatalf("post-invalidation read failed: %v", err)
	}

	if base.createRoleCalls != 1 || base.updateRoleCalls != 1 || base.deleteRoleCalls != 1 {
		t.Fatalf("expected one create/update/delete role call, got create=%d update=%d delete=%d", base.createRoleCalls, base.updateRoleCalls, base.deleteRoleCalls)
	}
	if base.roleDefinitionsCalls != 2 {
		t.Fatalf("expected cache flush to force second backend read, got %d", base.roleDefinitionsCalls)
	}
}
