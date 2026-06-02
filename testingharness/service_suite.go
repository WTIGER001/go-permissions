package testingharness

import (
	"context"
	"sort"
	"testing"

	"github.com/wtiger001/go-permissions"
)

type EffectiveExpectation struct {
	UserID          string
	TeamID          *int64
	ExpectedPerms   []string
	UnexpectedPerms []string
}

type HarnessStore interface {
	permissions.PermissionStore
	permissions.IdentityProvider

	HarnessName() string
	Reset(ctx context.Context, t *testing.T)
	SeedDenyOverridesAllow(ctx context.Context, t *testing.T) permissions.Request
	SeedStrictBindingError(ctx context.Context, t *testing.T) permissions.Request
	SeedEffectivePermissions(ctx context.Context, t *testing.T) EffectiveExpectation
	SeedTransitiveRoles(ctx context.Context, t *testing.T) permissions.Request
}

type Harness struct {
	store HarnessStore
}

func NewHarness(store HarnessStore) *Harness {
	return &Harness{store: store}
}

func (h *Harness) RunAll(t *testing.T) {
	t.Helper()

	if h.store == nil {
		t.Fatalf("harness store is required")
	}

	name := h.store.HarnessName()
	if name == "" {
		t.Fatalf("service suite name is required")
	}

	t.Run(name+"/HasPermission_deny_overrides_allow", func(t *testing.T) {
		ctx := context.Background()
		h.store.Reset(ctx, t)
		svc := permissions.NewServiceWithProviders(h.store, h.store)

		req := h.store.SeedDenyOverridesAllow(ctx, t)
		allowed, err := svc.HasPermission(ctx, req)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if allowed {
			t.Fatalf("expected denied result due to matching deny grant")
		}
	})

	t.Run(name+"/HasPermission_strict_binding_error", func(t *testing.T) {
		ctx := context.Background()
		h.store.Reset(ctx, t)
		svc := permissions.NewServiceWithProviders(h.store, h.store)

		req := h.store.SeedStrictBindingError(ctx, t)
		_, err := svc.HasPermission(ctx, req)
		if err == nil {
			t.Fatalf("expected strict binding error, got nil")
		}
	})

	t.Run(name+"/EffectivePermissions_filters_denied", func(t *testing.T) {
		ctx := context.Background()
		h.store.Reset(ctx, t)
		svc := permissions.NewServiceWithProviders(h.store, h.store)

		expect := h.store.SeedEffectivePermissions(ctx, t)
		perms, err := svc.EffectivePermissions(ctx, expect.UserID, expect.TeamID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		got := make([]string, 0, len(perms))
		for _, p := range perms {
			got = append(got, p.PermissionName)
		}
		sort.Strings(got)

		expected := append([]string(nil), expect.ExpectedPerms...)
		sort.Strings(expected)

		if len(got) != len(expected) {
			t.Fatalf("expected permissions %v, got %v", expected, got)
		}
		for i := range expected {
			if got[i] != expected[i] {
				t.Fatalf("expected permissions %v, got %v", expected, got)
			}
		}

		unexpectedSet := map[string]bool{}
		for _, p := range expect.UnexpectedPerms {
			unexpectedSet[p] = true
		}
		for _, p := range got {
			if unexpectedSet[p] {
				t.Fatalf("permission %q should have been filtered out", p)
			}
		}
	})

	// HasPermission via multi-hop transitive role inheritance:
	// user -> r-top -> r-mid -> r-leaf (grant is on r-leaf).
	t.Run(name+"/HasPermission_transitive_role_inheritance", func(t *testing.T) {
		ctx := context.Background()
		h.store.Reset(ctx, t)
		svc := permissions.NewServiceWithProviders(h.store, h.store)

		req := h.store.SeedTransitiveRoles(ctx, t)
		allowed, err := svc.HasPermission(ctx, req)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !allowed {
			t.Fatalf("expected allowed result via transitive role chain")
		}
	})
}
