package cachedstore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/wtiger001/go-permissions"
)

type countingStore struct {
	mu                   sync.Mutex
	isUserInGroupCalls   int
	knownGroupCalls      int
	grantsCalls          int
	roleAssignWriteCalls int
	grantWriteCalls      int
}

func (s *countingStore) IsUserInGroup(_ context.Context, userID, groupID string) (bool, error) {
	s.mu.Lock()
	s.isUserInGroupCalls++
	s.mu.Unlock()
	return userID == "u-1" && groupID == "g-1", nil
}

func (s *countingStore) ListKnownGroupIDs(_ context.Context) ([]string, error) {
	s.mu.Lock()
	s.knownGroupCalls++
	s.mu.Unlock()
	return []string{"g-1", "g-2"}, nil
}

func (s *countingStore) ListRoleAssignmentsForUserAndGroups(_ context.Context, _ string, _ []string) ([]permissions.RoleAssignment, error) {
	return nil, nil
}

func (s *countingStore) ListExpandedRoleIDs(_ context.Context, _ []string) ([]string, error) {
	return nil, nil
}

func (s *countingStore) ListGrantsForOwners(_ context.Context, _ []permissions.PrincipalRef, _ permissions.Request) ([]permissions.Grant, error) {
	s.mu.Lock()
	s.grantsCalls++
	s.mu.Unlock()
	return []permissions.Grant{{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "p.read"}}, nil
}

func (s *countingStore) ListPrincipalsWithGrant(_ context.Context, _ permissions.Request) ([]permissions.PrincipalHit, error) {
	return nil, nil
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

func TestStore_CachesReadResults(t *testing.T) {
	base := &countingStore{}
	store := NewStoreWithTTL(base, time.Minute)
	ctx := context.Background()

	if _, err := store.ListKnownGroupIDs(ctx); err != nil {
		t.Fatalf("first list known groups failed: %v", err)
	}
	if _, err := store.ListKnownGroupIDs(ctx); err != nil {
		t.Fatalf("second list known groups failed: %v", err)
	}

	if _, err := store.IsUserInGroup(ctx, "u-1", "g-1"); err != nil {
		t.Fatalf("first membership check failed: %v", err)
	}
	if _, err := store.IsUserInGroup(ctx, "u-1", "g-1"); err != nil {
		t.Fatalf("second membership check failed: %v", err)
	}

	if _, err := store.ListGrantsForOwners(ctx, []permissions.PrincipalRef{{Kind: permissions.PrincipalUser, ID: "u-1"}}, permissions.Request{UserID: "u-1", Perm: "p.read"}); err != nil {
		t.Fatalf("first grants lookup failed: %v", err)
	}
	if _, err := store.ListGrantsForOwners(ctx, []permissions.PrincipalRef{{Kind: permissions.PrincipalUser, ID: "u-1"}}, permissions.Request{UserID: "u-1", Perm: "p.read"}); err != nil {
		t.Fatalf("second grants lookup failed: %v", err)
	}

	if base.knownGroupCalls != 1 {
		t.Fatalf("expected 1 known-group call, got %d", base.knownGroupCalls)
	}
	if base.isUserInGroupCalls != 1 {
		t.Fatalf("expected 1 membership call, got %d", base.isUserInGroupCalls)
	}
	if base.grantsCalls != 1 {
		t.Fatalf("expected 1 grants call, got %d", base.grantsCalls)
	}
}

func TestStore_InvalidateOnWrites(t *testing.T) {
	base := &countingStore{}
	store := NewStoreWithTTL(base, time.Minute)
	ctx := context.Background()

	if _, err := store.ListKnownGroupIDs(ctx); err != nil {
		t.Fatalf("prime cache failed: %v", err)
	}
	if _, err := store.ListKnownGroupIDs(ctx); err != nil {
		t.Fatalf("cache hit failed: %v", err)
	}

	if err := store.CreateGrant(ctx, permissions.Grant{OwnerKind: permissions.PrincipalUser, OwnerID: "u-1", Effect: permissions.EffectAllow, TeamScope: "*", PermissionName: "p.read"}); err != nil {
		t.Fatalf("create grant failed: %v", err)
	}

	if _, err := store.ListKnownGroupIDs(ctx); err != nil {
		t.Fatalf("post-invalidation read failed: %v", err)
	}

	if base.grantWriteCalls != 1 {
		t.Fatalf("expected 1 grant write call, got %d", base.grantWriteCalls)
	}
	if base.knownGroupCalls != 2 {
		t.Fatalf("expected cache flush to force second backend read, got %d calls", base.knownGroupCalls)
	}
}

func TestStore_TTLExpiry(t *testing.T) {
	base := &countingStore{}
	store := NewStoreWithTTL(base, 30*time.Millisecond)
	ctx := context.Background()

	if _, err := store.IsUserInGroup(ctx, "u-1", "g-1"); err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if _, err := store.IsUserInGroup(ctx, "u-1", "g-1"); err != nil {
		t.Fatalf("cached read failed: %v", err)
	}
	if base.isUserInGroupCalls != 1 {
		t.Fatalf("expected 1 backend call before TTL expiry, got %d", base.isUserInGroupCalls)
	}

	time.Sleep(50 * time.Millisecond)
	if _, err := store.IsUserInGroup(ctx, "u-1", "g-1"); err != nil {
		t.Fatalf("post-expiry read failed: %v", err)
	}
	if base.isUserInGroupCalls != 2 {
		t.Fatalf("expected backend call after TTL expiry, got %d", base.isUserInGroupCalls)
	}
}
