package inmemory

import (
	"context"
	"slices"
	"sync"

	"github.com/wtiger001/go-permissions"
)

type TeamMembershipPrincipalKind string

var UserMemberKind TeamMembershipPrincipalKind = "user"
var GroupMemberKind TeamMembershipPrincipalKind = "group"

type Entry struct {
	ID   string
	Kind TeamMembershipPrincipalKind
}

type IdentityProvider struct {
	mu             sync.RWMutex
	userGroups     map[string][]string
	teamMembership map[string][]Entry
}

var _ permissions.IdentityProvider = (*IdentityProvider)(nil)

func NewIdentityProvider() *IdentityProvider {
	return &IdentityProvider{userGroups: map[string][]string{}}
}

func (p *IdentityProvider) AddUserGroups(userID string, groupIDs ...string) {
	if userID == "" || len(groupIDs) == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.userGroups[userID] = append(p.userGroups[userID], groupIDs...)
}

func (p *IdentityProvider) GetUserGroups(_ context.Context, userID string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return append([]string(nil), p.userGroups[userID]...), nil
}

func (p *IdentityProvider) GetGroupMembers(_ context.Context, groupID string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	members := make([]string, 0)
	for userID, groups := range p.userGroups {
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

	for _, candidate := range p.userGroups[userID] {
		if candidate == groupID {
			return true, nil
		}
	}

	return false, nil
}

func (p *IdentityProvider) GetUserTeams(c context.Context, userID string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	teams := make([]string, 0)

	for teamID, entries := range p.teamMembership {
		for _, entry := range entries {
			if entry.ID == userID && entry.Kind == UserMemberKind {
				teams = append(teams, teamID)
				continue
			} else if entry.Kind == GroupMemberKind {
				inGroup, _ := p.IsUserInGroup(c, userID, entry.ID)
				if inGroup {
					teams = append(teams, teamID)
					continue
				}
			}
		}
	}

	return append([]string(nil), teams...), nil
}

func (p *IdentityProvider) IsUserInTeam(c context.Context, userID, teamID string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	teams, err := p.GetUserTeams(c, userID)
	if err != nil {
		return false, err
	}
	return slices.Contains(teams, teamID), nil
}
