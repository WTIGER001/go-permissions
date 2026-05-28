package jsonstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityProvider_LoadSaveAndMembershipQueries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")

	p, err := NewIdentityProvider(path)
	if err != nil {
		t.Fatalf("NewIdentityProvider: %v", err)
	}

	if err := p.SetUserGroups("u-1", []string{"g-1", "g-2"}); err != nil {
		t.Fatalf("SetUserGroups u-1: %v", err)
	}
	if err := p.SetUserGroups("u-2", []string{"g-2"}); err != nil {
		t.Fatalf("SetUserGroups u-2: %v", err)
	}

	reloaded, err := NewIdentityProvider(path)
	if err != nil {
		t.Fatalf("reload identity provider: %v", err)
	}

	groups, err := reloaded.GetUserGroups(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("GetUserGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 user groups, got %d", len(groups))
	}

	members, err := reloaded.GetGroupMembers(context.Background(), "g-2")
	if err != nil {
		t.Fatalf("GetGroupMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 group members, got %d", len(members))
	}

	inGroup, err := reloaded.IsUserInGroup(context.Background(), "u-1", "g-1")
	if err != nil {
		t.Fatalf("IsUserInGroup true: %v", err)
	}
	if !inGroup {
		t.Fatalf("expected user in group")
	}

	notInGroup, err := reloaded.IsUserInGroup(context.Background(), "u-1", "missing")
	if err != nil {
		t.Fatalf("IsUserInGroup false: %v", err)
	}
	if notInGroup {
		t.Fatalf("expected user not in missing group")
	}
}

func TestIdentityProvider_LoadEdgeCases(t *testing.T) {
	t.Run("empty path rejected", func(t *testing.T) {
		if _, err := NewIdentityProvider(""); err == nil {
			t.Fatalf("expected path validation error")
		}
	})

	t.Run("invalid json returns error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
			t.Fatalf("write invalid json: %v", err)
		}
		if _, err := NewIdentityProvider(path); err == nil {
			t.Fatalf("expected invalid json error")
		}
	})

	t.Run("empty file initializes empty state", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identity.json")
		if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
			t.Fatalf("write empty file: %v", err)
		}
		p, err := NewIdentityProvider(path)
		if err != nil {
			t.Fatalf("new provider on empty file: %v", err)
		}
		groups, err := p.GetUserGroups(context.Background(), "missing")
		if err != nil {
			t.Fatalf("GetUserGroups on empty state: %v", err)
		}
		if len(groups) != 0 {
			t.Fatalf("expected empty groups on empty file")
		}
	})
}
