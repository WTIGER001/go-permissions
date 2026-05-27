package jsonstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/wtiger001/go-permissions"
)

type IdentityData struct {
	UserGroups map[string][]string `json:"user_groups"`
}

type IdentityProvider struct {
	path string
	mu   sync.RWMutex
	data IdentityData
}

var _ permissions.IdentityProvider = (*IdentityProvider)(nil)

func NewIdentityProvider(path string) (*IdentityProvider, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}

	p := &IdentityProvider{path: path, data: emptyIdentityData()}
	if err := p.Load(); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *IdentityProvider) Load() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	content, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			p.data = emptyIdentityData()
			return nil
		}
		return fmt.Errorf("read identity file: %w", err)
	}

	if len(content) == 0 {
		p.data = emptyIdentityData()
		return nil
	}

	var parsed IdentityData
	if err := json.Unmarshal(content, &parsed); err != nil {
		return fmt.Errorf("decode identity file: %w", err)
	}

	p.data = normalizeIdentityData(parsed)
	return nil
}

func (p *IdentityProvider) Save() error {
	p.mu.RLock()
	data := cloneIdentityData(p.data)
	p.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}

	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity data: %w", err)
	}

	tmpPath := p.path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o644); err != nil {
		return fmt.Errorf("write temp identity file: %w", err)
	}

	if err := os.Rename(tmpPath, p.path); err != nil {
		return fmt.Errorf("replace identity file: %w", err)
	}

	return nil
}

func (p *IdentityProvider) SetUserGroups(userID string, groupIDs []string) error {
	p.mu.Lock()
	p.data.UserGroups[userID] = append([]string(nil), groupIDs...)
	p.mu.Unlock()

	return p.Save()
}

func (p *IdentityProvider) GetUserGroups(_ context.Context, userID string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return append([]string(nil), p.data.UserGroups[userID]...), nil
}

func (p *IdentityProvider) GetGroupMembers(_ context.Context, groupID string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	members := make([]string, 0)
	for userID, groups := range p.data.UserGroups {
		for _, candidate := range groups {
			if candidate == groupID {
				members = append(members, userID)
				break
			}
		}
	}

	return members, nil
}

func (p *IdentityProvider) IsUserInGroup(_ context.Context, userID, groupID string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, candidate := range p.data.UserGroups[userID] {
		if candidate == groupID {
			return true, nil
		}
	}

	return false, nil
}

func emptyIdentityData() IdentityData {
	return IdentityData{UserGroups: map[string][]string{}}
}

func normalizeIdentityData(data IdentityData) IdentityData {
	if data.UserGroups == nil {
		data.UserGroups = map[string][]string{}
	}
	return data
}

func cloneIdentityData(data IdentityData) IdentityData {
	cloned := IdentityData{UserGroups: map[string][]string{}}
	for userID, groups := range data.UserGroups {
		cloned.UserGroups[userID] = append([]string(nil), groups...)
	}
	return cloned
}
