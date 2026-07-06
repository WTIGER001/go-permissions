package permissions

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Service struct {
	identity            IdentityProvider
	permissions         PermissionStore
	builtIns            *builtInRegistry
	disabledCache       map[string]bool
	disabledCacheAt     time.Time
	disabledCacheMu     sync.RWMutex
	publicRoleID        string
	authenticatedRoleID string
	adminRoleID         string
	adminGroupID        string
}

// New creates a service with a nil identity provider and an in-memory default store.
func New() *Service {
	service := &Service{
		permissions: newBootstrapStore(),
		builtIns:    newBuiltInRegistry(),
	}
	service.applyDefaultSyntheticRoleIDs()
	return service
}

// NewService wires the service to a permission store and identity provider.
func NewService(permissionStore PermissionStore, identityProvider IdentityProvider) *Service {
	if permissionStore == nil {
		permissionStore = newBootstrapStore()
	}
	service := &Service{
		identity:    identityProvider,
		permissions: permissionStore,
		builtIns:    newBuiltInRegistry(),
	}
	service.applyDefaultSyntheticRoleIDs()
	return service
}

// SetIdentityProvider updates the identity provider used by permission checks.
func (s *Service) SetIdentityProvider(identity IdentityProvider) {
	s.identity = identity
}

// SetStore updates the permission store and immediately re-runs built-in seeding.
func (s *Service) SetStore(store PermissionStore) error {
	if store == nil {
		store = newBootstrapStore()
	}
	s.permissions = store
	s.invalidateDisabledCache()
	return nil
}

// SetBuiltInGrants configures built-in grants used by SaveBuiltIns and SetStore bootstrap.
func (s *Service) SetBuiltInGrants(grants []Grant) {
	_ = s.SaveBuiltIns(context.Background(), grants)
}

// AddDefaultGrant appends an allow grant to built-in defaults and deduplicates equivalent entries.
// Invalid input indicates a programming error and triggers panic.
func (s *Service) AddDefaultGrant(roleID, permission, teamScope string) {
	roleID = strings.TrimSpace(roleID)
	permission = strings.TrimSpace(permission)
	teamScope = strings.TrimSpace(teamScope)
	if roleID == "" {
		panic("role ID is required")
	}
	if permission == "" {
		panic("permission name is required")
	}
	if teamScope == "" {
		teamScope = "*"
	}

	if !strings.HasPrefix(roleID, BuiltInPrefix) {
		roleID = BuiltInPrefix + roleID
	}

	grant := Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        roleID,
		Effect:         EffectAllow,
		TeamScope:      teamScope,
		PermissionName: permission,
	}

	_ = s.builtIns.AddGrant(grant)
}

// AddDefaultSystemCRUDGrants adds default allow grants for all system CRUD permissions.
func (s *Service) AddDefaultSystemCRUDGrants(roleID, teamScope string, crud SystemCRUDPermissions) {
	s.AddDefaultGrant(roleID, crud.Create.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Read.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Update.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Delete.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Grant.ID(), teamScope)
}

// AddDefaultTeamCRUDGrants adds default allow grants for all team CRUD permissions.
func (s *Service) AddDefaultTeamCRUDGrants(roleID, teamScope string, crud TeamCRUDPermissions) {
	s.AddDefaultGrant(roleID, crud.Create.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Read.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Update.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Delete.ID(), teamScope)
	s.AddDefaultGrant(roleID, crud.Grant.ID(), teamScope)
}

// AddDefaultCRUDGrant adds a default allow grant for a single CRUD action.
func (s *Service) AddDefaultCRUDGrant(roleID, teamScope string, action CRUDAction, permissionID string) {
	switch action {
	case CRUDCreate, CRUDRead, CRUDUpdate, CRUDDelete, CRUDGrant:
		s.AddDefaultGrant(roleID, permissionID, teamScope)
	default:
		panic("invalid CRUD action")
	}
}

func (s *Service) applyDefaultSyntheticRoleIDs() {
	if strings.TrimSpace(s.publicRoleID) == "" {
		s.publicRoleID = SyntheticRolePublic
	}
	if strings.TrimSpace(s.authenticatedRoleID) == "" {
		s.authenticatedRoleID = SyntheticRoleAuthenticated
	}
	if strings.TrimSpace(s.adminRoleID) == "" {
		s.adminRoleID = SyntheticRoleAdmin
	}
}

// SetPublicRoleID configures the synthetic role applied to anonymous requests.
func (s *Service) SetPublicRoleID(roleID string) {
	s.publicRoleID = strings.TrimSpace(roleID)
}

// SetAuthenticatedRoleID configures the synthetic role applied to authenticated requests.
func (s *Service) SetAuthenticatedRoleID(roleID string) {
	s.authenticatedRoleID = strings.TrimSpace(roleID)
}

// SetAdminRoleID configures the synthetic role applied to users in the configured admin group.
func (s *Service) SetAdminRoleID(roleID string) {
	s.adminRoleID = strings.TrimSpace(roleID)
}

// SetAdminGroupID configures which group grants the synthetic admin role.
func (s *Service) SetAdminGroupID(groupID string) {
	s.adminGroupID = strings.TrimSpace(groupID)
}

// SetSyntheticRoleIDs configures all synthetic role IDs at once.
func (s *Service) SetSyntheticRoleIDs(publicRoleID, authenticatedRoleID, adminRoleID string) {
	s.publicRoleID = strings.TrimSpace(publicRoleID)
	s.authenticatedRoleID = strings.TrimSpace(authenticatedRoleID)
	s.adminRoleID = strings.TrimSpace(adminRoleID)
}

// NewServiceWithProviders is an alias for NewService.
func NewServiceWithProviders(permissionStore PermissionStore, identityProvider IdentityProvider) *Service {
	return NewService(permissionStore, identityProvider)
}

// NewServiceWithIdentity wires a custom identity provider with a permission store.
// This is the recommended constructor when users/groups/memberships are managed externally.
func NewServiceWithIdentity(identity IdentityProvider, permissionStore PermissionStore) *Service {
	return NewService(permissionStore, identity)
}

func (s *Service) AllowUser(ctx context.Context, userID, permission string, objectID *string) error {
	return s.CreateGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
	})
}

func (s *Service) AllowUserUntil(ctx context.Context, userID, permission string, objectID *string, expiresAt time.Time) error {
	return s.CreateGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
		ExpiresAt:      cloneTimePointer(&expiresAt),
	})
}

func (s *Service) AllowUserFor(ctx context.Context, userID, permission string, objectID *string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl must be greater than zero")
	}
	return s.AllowUserUntil(ctx, userID, permission, objectID, time.Now().UTC().Add(ttl))
}

func (s *Service) DenyUser(ctx context.Context, userID, permission string, objectID *string) error {
	return s.CreateGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectDeny,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
	})
}

func (s *Service) DenyUserUntil(ctx context.Context, userID, permission string, objectID *string, expiresAt time.Time) error {
	return s.CreateGrant(ctx, Grant{
		OwnerKind:      PrincipalUser,
		OwnerID:        userID,
		Effect:         EffectDeny,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
		ExpiresAt:      cloneTimePointer(&expiresAt),
	})
}

func (s *Service) DenyUserFor(ctx context.Context, userID, permission string, objectID *string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl must be greater than zero")
	}
	return s.DenyUserUntil(ctx, userID, permission, objectID, time.Now().UTC().Add(ttl))
}

func (s *Service) AllowRole(ctx context.Context, roleID, permission string, objectID *string) error {
	return s.CreateGrant(ctx, Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        roleID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
	})
}

func (s *Service) AllowRoleUntil(ctx context.Context, roleID, permission string, objectID *string, expiresAt time.Time) error {
	return s.CreateGrant(ctx, Grant{
		OwnerKind:      PrincipalRole,
		OwnerID:        roleID,
		Effect:         EffectAllow,
		TeamScope:      "*",
		ObjectScope:    cloneStringPointer(objectID),
		PermissionName: permission,
		ExpiresAt:      cloneTimePointer(&expiresAt),
	})
}

func (s *Service) AllowRoleFor(ctx context.Context, roleID, permission string, objectID *string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl must be greater than zero")
	}
	return s.AllowRoleUntil(ctx, roleID, permission, objectID, time.Now().UTC().Add(ttl))
}

func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleID string, bindingValues map[string]any) error {
	if userID == "" {
		return fmt.Errorf("user ID is required")
	}
	if roleID == "" {
		return fmt.Errorf("role ID is required")
	}

	copyBinding := map[string]any{}
	for k, v := range bindingValues {
		copyBinding[k] = v
	}

	return s.permissions.AssignRole(ctx, PrincipalRef{Kind: PrincipalUser, ID: userID}, roleID, copyBinding)
}

func (s *Service) HasSystemPermission(ctx context.Context, userID string, perm string) (bool, error) {
	return s.HasPermission(ctx, Request{UserID: userID, Perm: perm})
}

func (s *Service) HasTeamPermission(ctx context.Context, userID string, teamID string, object, perm string) (bool, error) {
	return s.HasPermission(ctx, Request{UserID: userID, TeamID: teamID, Object: object, Perm: perm})
}

func (s *Service) HasFieldPermission(ctx context.Context, req Request, fieldPath string) (bool, error) {
	if isIndexedFieldPath(fieldPath) {
		return false, fmt.Errorf("indexed field paths are not supported: %q", fieldPath)
	}
	if strings.TrimSpace(fieldPath) == "" {
		return false, fmt.Errorf("field path is required")
	}

	return s.evaluatePermission(ctx, req, &fieldPath)
}

func (s *Service) FilterPermittedFields(ctx context.Context, req Request, fieldPaths []string) ([]string, error) {
	result := make([]string, 0, len(fieldPaths))
	seen := make(map[string]bool, len(fieldPaths))

	for _, path := range fieldPaths {
		if seen[path] {
			continue
		}
		seen[path] = true

		allowed, err := s.HasFieldPermission(ctx, req, path)
		if err != nil {
			return nil, err
		}
		if allowed {
			result = append(result, path)
		}
	}

	return result, nil
}

func (s *Service) HasPermission(ctx context.Context, req Request) (bool, error) {
	return s.evaluatePermission(ctx, req, nil)
}

func (s *Service) evaluatePermission(ctx context.Context, req Request, fieldPath *string) (bool, error) {
	if req.Perm == "" {
		return false, fmt.Errorf("permission name is required")
	}

	now := time.Now().UTC()

	groupIDs, err := s.resolveUserGroupIDs(ctx, req.UserID)
	if err != nil {
		return false, err
	}

	roleAssignments, err := s.resolveRoleAssignmentsForUserAndGroups(ctx, req.UserID, groupIDs)
	if err != nil {
		return false, err
	}

	// Phase 1: evaluate grants for the user and their groups (no binding resolution needed).
	unboundOwners := make([]PrincipalRef, 0, 1+len(groupIDs))
	if req.UserID != "" {
		unboundOwners = append(unboundOwners, PrincipalRef{Kind: PrincipalUser, ID: req.UserID})
	}
	for _, groupID := range groupIDs {
		unboundOwners = append(unboundOwners, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
	}

	var allowed bool
	if len(unboundOwners) > 0 {
		unboundGrants, err := s.permissions.GrantsForOwners(ctx, unboundOwners, req)
		if err != nil {
			return false, err
		}
		for _, grant := range unboundGrants {
			if grant.IsExpiredAt(now) {
				continue
			}
			if !grantMatchesRequest(grant, req) || !grantMatchesFieldPath(grant, fieldPath) {
				continue
			}
			if grant.Effect == EffectDeny {
				if fieldPath == nil && len(grant.RestrictedFields) > 0 {
					continue
				}
				return false, nil
			}
			allowed = true
		}
	}

	// Phase 2: evaluate role-based grants per assignment so that each assignment's
	// binding values are resolved independently. This prevents overwriting bindings
	// when the same role is held with different values (e.g. team.viewer in Team 42
	// and Team 99 simultaneously).
	//
	// ExpandRoles results are memoised within the request to avoid redundant store
	// calls when multiple assignments share the same root role.
	expandCache := map[string][]string{}

	for _, assignment := range roleAssignments {
		roleIDs, err := s.expandRolesCached(ctx, assignment.RoleID, expandCache)
		if err != nil {
			return false, err
		}

		roleGrants, err := s.fetchRoleGrants(ctx, roleIDs, req)
		if err != nil {
			return false, err
		}

		// Build a single-entry binding map for this assignment so resolveGrantBindings
		// can resolve variable scopes correctly.
		bindingMap := map[string]map[string]any{
			assignment.RoleID: assignment.BindingValues,
		}

		roleIDSet := make(map[string]bool, len(roleIDs))
		for _, rID := range roleIDs {
			roleIDSet[rID] = true
		}

		for _, grant := range roleGrants {
			if grant.OwnerKind == PrincipalRole && !roleIDSet[grant.OwnerID] {
				continue
			}
			if grant.IsExpiredAt(now) {
				continue
			}
			resolvedGrant, err := resolveGrantBindings(grant, bindingMap)
			if err != nil {
				return false, err
			}
			if !grantMatchesRequest(resolvedGrant, req) || !grantMatchesFieldPath(resolvedGrant, fieldPath) {
				continue
			}
			if resolvedGrant.Effect == EffectDeny {
				if fieldPath == nil && len(resolvedGrant.RestrictedFields) > 0 {
					continue
				}
				return false, nil
			}
			allowed = true
		}
	}

	return allowed, nil
}

func (s *Service) fetchRoleGrants(ctx context.Context, roleIDs []string, req Request) ([]Grant, error) {
	var builtInOwners []PrincipalRef
	var customOwners []PrincipalRef
	for _, rID := range roleIDs {
		ref := PrincipalRef{Kind: PrincipalRole, ID: rID}
		if strings.HasPrefix(rID, BuiltInPrefix) {
			builtInOwners = append(builtInOwners, ref)
		} else {
			customOwners = append(customOwners, ref)
		}
	}

	var roleGrants []Grant
	if len(builtInOwners) > 0 {
		roleGrants = append(roleGrants, s.builtIns.GrantsForOwners(builtInOwners, req)...)
	}
	if len(customOwners) > 0 {
		cg, err := s.permissions.GrantsForOwners(ctx, customOwners, req)
		if err != nil {
			return nil, err
		}
		roleGrants = append(roleGrants, cg...)
	}
	return roleGrants, nil
}

func (s *Service) getDisabledBuiltInRoles(ctx context.Context) (map[string]bool, error) {
	s.disabledCacheMu.RLock()
	if time.Since(s.disabledCacheAt) < 5*time.Second && s.disabledCache != nil {
		cacheCopy := make(map[string]bool, len(s.disabledCache))
		for k, v := range s.disabledCache {
			cacheCopy[k] = v
		}
		s.disabledCacheMu.RUnlock()
		return cacheCopy, nil
	}
	s.disabledCacheMu.RUnlock()

	s.disabledCacheMu.Lock()
	defer s.disabledCacheMu.Unlock()

	if time.Since(s.disabledCacheAt) < 5*time.Second && s.disabledCache != nil {
		cacheCopy := make(map[string]bool, len(s.disabledCache))
		for k, v := range s.disabledCache {
			cacheCopy[k] = v
		}
		return cacheCopy, nil
	}

	disabledList, err := s.permissions.DisabledBuiltInRoles(ctx)
	if err != nil {
		return nil, err
	}

	cache := make(map[string]bool, len(disabledList))
	for _, id := range disabledList {
		cache[id] = true
	}
	s.disabledCache = cache
	s.disabledCacheAt = time.Now()

	cacheCopy := make(map[string]bool, len(cache))
	for k, v := range cache {
		cacheCopy[k] = v
	}
	return cacheCopy, nil
}

func (s *Service) invalidateDisabledCache() {
	s.disabledCacheMu.Lock()
	defer s.disabledCacheMu.Unlock()
	s.disabledCacheAt = time.Time{}
}

// expandRolesCached calls ExpandRoles and memoises the result so that multiple
// assignments sharing the same root role only hit the store once per request.
func (s *Service) expandRolesCached(ctx context.Context, rootRoleID string, cache map[string][]string) ([]string, error) {
	if cached, ok := cache[rootRoleID]; ok {
		return cached, nil
	}

	disabledMap, err := s.getDisabledBuiltInRoles(ctx)
	if err != nil {
		disabledMap = map[string]bool{}
	}

	var expanded []string
	if strings.HasPrefix(rootRoleID, BuiltInPrefix) {
		expanded = s.builtIns.ExpandRoles([]string{rootRoleID})
	} else {
		dbExpanded, err := s.permissions.ExpandRoles(ctx, []string{rootRoleID})
		if err != nil {
			return nil, err
		}
		expanded = s.builtIns.ExpandRoles(dbExpanded)
	}

	filtered := make([]string, 0, len(expanded))
	for _, rID := range expanded {
		if disabledMap[rID] {
			continue
		}
		roleDef, err := s.RoleDefinition(ctx, rID)
		if err == nil && roleDef.IsDisabled {
			continue
		}
		filtered = append(filtered, rID)
	}
	cache[rootRoleID] = filtered
	return filtered, nil
}

func (s *Service) EffectivePermissions(ctx context.Context, userID string, teamID string) ([]EffectivePermission, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	now := time.Now().UTC()

	groupIDs, err := s.resolveUserGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}

	roleAssignments, err := s.resolveRoleAssignmentsForUserAndGroups(ctx, userID, groupIDs)
	if err != nil {
		return nil, err
	}

	denied := map[string]bool{}
	allowed := map[string]EffectivePermission{}

	accumulateGrant := func(resolvedGrant Grant) {
		if !matchesTeamScope(resolvedGrant, teamID) {
			return
		}
		key := permissionKey(resolvedGrant)
		if resolvedGrant.Effect == EffectDeny {
			denied[key] = true
			delete(allowed, key)
			return
		}
		if denied[key] {
			return
		}
		if _, exists := allowed[key]; exists {
			return
		}
		allowed[key] = EffectivePermission{
			TeamScope:        resolvedGrant.TeamScope,
			ObjectScope:      resolvedGrant.ObjectScope,
			PermissionName:   resolvedGrant.PermissionName,
			Source:           PrincipalRef{Kind: resolvedGrant.OwnerKind, ID: resolvedGrant.OwnerID},
			Effect:           resolvedGrant.Effect,
			RestrictedFields: append([]string(nil), resolvedGrant.RestrictedFields...),
		}
	}

	baseReq := Request{UserID: userID, TeamID: teamID}

	// Phase 1: unbound principals (user + groups).
	unboundOwners := make([]PrincipalRef, 0, 1+len(groupIDs))
	unboundOwners = append(unboundOwners, PrincipalRef{Kind: PrincipalUser, ID: userID})
	for _, groupID := range groupIDs {
		unboundOwners = append(unboundOwners, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
	}

	unboundGrants, err := s.permissions.GrantsForOwners(ctx, unboundOwners, baseReq)
	if err != nil {
		return nil, err
	}
	for _, grant := range unboundGrants {
		if !grant.IsExpiredAt(now) {
			accumulateGrant(grant)
		}
	}

	// Phase 2: per-assignment role evaluation so each assignment's bindings are
	// resolved independently.
	expandCache := map[string][]string{}

	for _, assignment := range roleAssignments {
		roleIDs, err := s.expandRolesCached(ctx, assignment.RoleID, expandCache)
		if err != nil {
			return nil, err
		}

		roleGrants, err := s.fetchRoleGrants(ctx, roleIDs, baseReq)
		if err != nil {
			return nil, err
		}

		bindingMap := map[string]map[string]any{
			assignment.RoleID: assignment.BindingValues,
		}

		roleIDSet := make(map[string]bool, len(roleIDs))
		for _, rID := range roleIDs {
			roleIDSet[rID] = true
		}

		for _, grant := range roleGrants {
			if grant.OwnerKind == PrincipalRole && !roleIDSet[grant.OwnerID] {
				continue
			}
			if grant.IsExpiredAt(now) {
				continue
			}
			resolvedGrant, err := resolveGrantBindings(grant, bindingMap)
			if err != nil {
				return nil, err
			}
			accumulateGrant(resolvedGrant)
		}
	}

	result := make([]EffectivePermission, 0, len(allowed))
	for _, eff := range allowed {
		result = append(result, eff)
	}

	return result, nil
}

func (s *Service) AllowedTeamsForUser(ctx context.Context, userID, perm string) (allTeams bool, teamIDs []string, err error) {
	if perm == "" {
		return false, nil, fmt.Errorf("permission name is required")
	}

	perms, err := s.EffectivePermissions(ctx, userID, "")
	if err != nil {
		return false, nil, err
	}

	seen := map[string]bool{}
	for _, p := range perms {
		if p.PermissionName == perm {
			if p.TeamScope == "*" {
				return true, nil, nil
			}
			if !seen[p.TeamScope] {
				teamIDs = append(teamIDs, p.TeamScope)
				seen[p.TeamScope] = true
			}
		}
	}

	return false, teamIDs, nil
}

func (s *Service) PrincipalsWithPermission(ctx context.Context, teamID string, object, perm string) ([]PrincipalHit, error) {
	if perm == "" {
		return nil, fmt.Errorf("permission name is required")
	}

	hits, err := s.permissions.PrincipalsWithGrant(ctx, Request{
		TeamID: teamID,
		Object: object,
		Perm:   perm,
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Kind != hits[j].Kind {
			return hits[i].Kind < hits[j].Kind
		}
		if hits[i].ID != hits[j].ID {
			return hits[i].ID < hits[j].ID
		}
		if hits[i].TeamScope != hits[j].TeamScope {
			return hits[i].TeamScope < hits[j].TeamScope
		}

		left := ""
		right := ""
		if hits[i].ObjectScope != nil {
			left = *hits[i].ObjectScope
		}
		if hits[j].ObjectScope != nil {
			right = *hits[j].ObjectScope
		}

		return left < right
	})

	return hits, nil
}

func grantMatchesRequest(grant Grant, req Request) bool {
	if grant.PermissionName != req.Perm {
		return false
	}

	if !matchesTeamScope(grant, req.TeamID) {
		return false
	}

	if grant.ObjectScope == nil {
		return true
	}

	objectScope := *grant.ObjectScope
	if objectScope == "*" {
		return true
	}

	return objectScope == req.Object
}

func grantMatchesFieldPath(grant Grant, fieldPath *string) bool {
	if fieldPath == nil {
		return true
	}

	if len(grant.RestrictedFields) == 0 {
		return true
	}

	matchesRestricted := false
	for _, restrictedPath := range grant.RestrictedFields {
		if fieldPathMatches(restrictedPath, *fieldPath) {
			matchesRestricted = true
			break
		}
	}

	if grant.Effect == EffectDeny {
		return matchesRestricted
	}

	return !matchesRestricted
}

func fieldPathMatches(grantPath, candidate string) bool {
	grantPath = strings.TrimSpace(grantPath)
	candidate = strings.TrimSpace(candidate)
	if grantPath == "" || candidate == "" {
		return false
	}
	if grantPath == candidate {
		return true
	}

	return strings.HasPrefix(candidate, grantPath+".")
}

func isIndexedFieldPath(path string) bool {
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		allDigits := true
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}

	return false
}

func matchesTeamScope(grant Grant, teamID string) bool {
	if teamID == "" {
		return grant.TeamScope == "*"
	}

	return grant.TeamScope == "*" || grant.TeamScope == teamID
}

func permissionKey(grant Grant) string {
	obj := ""
	if grant.ObjectScope != nil {
		obj = *grant.ObjectScope
	}
	return strings.Join([]string{grant.TeamScope, obj, grant.PermissionName}, "::")
}

func resolveGrantBindings(grant Grant, bindingByRoleID map[string]map[string]any) (Grant, error) {
	if len(grant.VariableSpec) == 0 {
		return grant, nil
	}

	bindingValues := map[string]any{}
	if grant.OwnerKind == PrincipalRole {
		var ok bool
		bindingValues, ok = bindingByRoleID[grant.OwnerID]
		if !ok {
			return Grant{}, fmt.Errorf("missing role binding for role ID %q", grant.OwnerID)
		}
	}

	for key, spec := range grant.VariableSpec {
		required, ok := spec.(string)
		if !ok {
			continue
		}
		if required == "required" {
			if _, exists := bindingValues[key]; !exists {
				return Grant{}, fmt.Errorf("missing required binding value %q for role ID %q", key, grant.OwnerID)
			}
		}
	}

	teamScope, err := resolveScopeToken(grant.TeamScope, bindingValues)
	if err != nil {
		return Grant{}, err
	}
	grant.TeamScope = teamScope

	if grant.ObjectScope != nil {
		resolved, err := resolveScopeToken(*grant.ObjectScope, bindingValues)
		if err != nil {
			return Grant{}, err
		}
		grant.ObjectScope = &resolved
	}

	return grant, nil
}

func resolveScopeToken(scope string, bindingValues map[string]any) (string, error) {
	if !strings.HasPrefix(scope, "?") {
		return scope, nil
	}

	name := strings.TrimPrefix(scope, "?")
	value, ok := bindingValues[name]
	if !ok {
		return "", fmt.Errorf("missing binding value for token %q", name)
	}

	switch typed := value.(type) {
	case string:
		return typed, nil
	case int:
		return strconv.Itoa(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case float64:
		return strconv.FormatInt(int64(typed), 10), nil
	default:
		return fmt.Sprintf("%v", value), nil
	}
}

func (s *Service) resolveUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	if userID == "" {
		return nil, nil
	}
	if s.identity == nil {
		return nil, nil
	}

	groupIDs, err := s.identity.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(groupIDs))
	seen := map[string]bool{}
	for _, groupID := range groupIDs {
		if seen[groupID] {
			continue
		}
		seen[groupID] = true
		result = append(result, groupID)
	}

	return result, nil
}

func (s *Service) resolveRoleAssignmentsForUserAndGroups(ctx context.Context, userID string, groupIDs []string) ([]RoleAssignment, error) {
	result := []RoleAssignment{}

	// Deduplicate on the (RoleID, BindingValues) pair so that identical duplicate
	// assignments are collapsed, but the same role held with *different* binding
	// values (e.g. team.viewer in Team 42 AND Team 99) is preserved as two
	// distinct entries.
	seenPairs := map[string]bool{}
	appendUnique := func(assignments []RoleAssignment) {
		for _, assignment := range assignments {
			if assignment.RoleID == "" {
				continue
			}
			roleDef, err := s.permissions.RoleDefinition(ctx, assignment.RoleID)
			if err == nil && roleDef.IsDisabled {
				continue
			}
			if assignment.BindingValues == nil {
				assignment.BindingValues = map[string]any{}
			}
			pairKey := assignmentKey(assignment)
			if seenPairs[pairKey] {
				continue
			}
			seenPairs[pairKey] = true
			result = append(result, assignment)
		}
	}

	if userID != "" {
		userAssignments, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: userID})
		if err != nil {
			return nil, err
		}
		appendUnique(userAssignments)
	}

	for _, groupID := range groupIDs {
		groupAssignments, err := s.permissions.RoleAssignmentsForPrincipal(ctx, PrincipalRef{Kind: PrincipalGroup, ID: groupID})
		if err != nil {
			return nil, err
		}
		appendUnique(groupAssignments)
	}

	appendUnique(s.syntheticRoleAssignments(userID, groupIDs))

	return result, nil
}

// assignmentKey returns a stable string key for a (RoleID, BindingValues) pair
// used to deduplicate role assignments without losing multi-tenant entries.
func assignmentKey(a RoleAssignment) string {
	if len(a.BindingValues) == 0 {
		return a.RoleID + ":"
	}
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(a.BindingValues))
	for k := range a.BindingValues {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(a.RoleID)
	sb.WriteByte(':')
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(fmt.Sprintf("%v", a.BindingValues[k]))
		sb.WriteByte(',')
	}
	return sb.String()
}

func (s *Service) syntheticRoleAssignments(userID string, groupIDs []string) []RoleAssignment {
	assignments := make([]RoleAssignment, 0, 3)

	if s.publicRoleID != "" {
		assignments = append(assignments, RoleAssignment{RoleID: s.publicRoleID, BindingValues: map[string]any{}})
	}

	if userID != "" && s.authenticatedRoleID != "" {
		assignments = append(assignments, RoleAssignment{RoleID: s.authenticatedRoleID, BindingValues: map[string]any{}})
	}

	if userID != "" && s.adminRoleID != "" && s.adminGroupID != "" && containsString(groupIDs, s.adminGroupID) {
		assignments = append(assignments, RoleAssignment{RoleID: s.adminRoleID, BindingValues: map[string]any{}})
	}

	return assignments
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

// CreateGrant registers a single grant. Built-in grants (where OwnerKind is PrincipalRole and OwnerID has prefix builtin.) are registered in memory, while custom grants are created in the store.
func (s *Service) CreateGrant(ctx context.Context, grant Grant) error {
	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		return fmt.Errorf("team scope is required")
	}

	if grant.OwnerKind == PrincipalRole && strings.HasPrefix(grant.OwnerID, BuiltInPrefix) {
		return s.builtIns.AddGrant(grant)
	}

	return s.permissions.CreateGrant(ctx, grant)
}

// CreateGrants writes multiple grants, using a store bulk path when available.
func (s *Service) CreateGrants(ctx context.Context, grants []Grant) error {
	if len(grants) == 0 {
		return nil
	}

	validated := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if grant.OwnerID == "" {
			return fmt.Errorf("owner ID is required")
		}
		if grant.PermissionName == "" {
			return fmt.Errorf("permission name is required")
		}
		if grant.TeamScope == "" {
			return fmt.Errorf("team scope is required")
		}
		validated = append(validated, cloneGrant(grant))
	}

	if bulkStore, ok := s.permissions.(BulkGrantStore); ok {
		return bulkStore.CreateGrants(ctx, validated)
	}

	for _, grant := range validated {
		if err := s.permissions.CreateGrant(ctx, grant); err != nil {
			return err
		}
	}

	return nil
}

// EnsureGrantsForOwners ensures each provided grant exists once and writes missing grants in bulk when supported.
func (s *Service) EnsureGrantsForOwners(ctx context.Context, grants []Grant) error {
	if len(grants) == 0 {
		return nil
	}

	missing := make([]Grant, 0, len(grants))
	now := time.Now().UTC()
	for _, grant := range grants {
		if grant.OwnerID == "" {
			return fmt.Errorf("owner ID is required")
		}
		if grant.PermissionName == "" {
			return fmt.Errorf("permission name is required")
		}
		if grant.TeamScope == "" {
			return fmt.Errorf("team scope is required")
		}

		principal := PrincipalRef{Kind: grant.OwnerKind, ID: grant.OwnerID}
		if err := principal.Validate(); err != nil {
			return err
		}

		existing, err := s.permissions.GrantsForPrincipal(ctx, principal)
		if err != nil {
			return err
		}

		exists := false
		for _, current := range existing {
			if current.IsExpiredAt(now) {
				continue
			}
			if grantsEquivalent(current, grant) {
				exists = true
				break
			}
		}

		if !exists {
			missing = append(missing, cloneGrant(grant))
		}
	}

	return s.CreateGrants(ctx, missing)
}

// EnsureSyntheticRoles ensures configured synthetic roles exist without overwriting existing definitions.
func (s *Service) EnsureSyntheticRoles(ctx context.Context) error {
	roles := []Role{}
	if s.publicRoleID != "" {
		roles = append(roles, Role{ID: s.publicRoleID, Name: s.publicRoleID, Description: "synthetic public role"})
	}
	if s.authenticatedRoleID != "" {
		roles = append(roles, Role{ID: s.authenticatedRoleID, Name: s.authenticatedRoleID, Description: "synthetic authenticated role"})
	}
	if s.adminRoleID != "" {
		roles = append(roles, Role{ID: s.adminRoleID, Name: s.adminRoleID, Description: "synthetic admin role"})
	}

	seen := map[string]bool{}
	for _, role := range roles {
		if role.ID == "" || seen[role.ID] {
			continue
		}
		seen[role.ID] = true
		if err := s.ensureRoleExists(ctx, role); err != nil {
			return err
		}
	}

	return nil
}

// EnsureGrantForOwner creates a grant only when an equivalent active grant does not already exist.
// This keeps startup/bootstrap flows idempotent across store implementations.
func (s *Service) EnsureGrantForOwner(ctx context.Context, grant Grant) error {
	if grant.OwnerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if grant.PermissionName == "" {
		return fmt.Errorf("permission name is required")
	}
	if grant.TeamScope == "" {
		return fmt.Errorf("team scope is required")
	}

	principal := PrincipalRef{Kind: grant.OwnerKind, ID: grant.OwnerID}
	if err := principal.Validate(); err != nil {
		return err
	}

	existing, err := s.permissions.GrantsForPrincipal(ctx, principal)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, current := range existing {
		if current.IsExpiredAt(now) {
			continue
		}
		if grantsEquivalent(current, grant) {
			return nil
		}
	}

	return s.permissions.CreateGrant(ctx, grant)
}

// DisableBuiltInRole disables a built-in role at runtime and invalidates the local cache.
func (s *Service) DisableBuiltInRole(ctx context.Context, roleID string) error {
	if err := s.permissions.DisableBuiltInRole(ctx, roleID); err != nil {
		return err
	}
	s.invalidateDisabledCache()
	return nil
}

// EnableBuiltInRole re-enables a built-in role at runtime and invalidates the local cache.
func (s *Service) EnableBuiltInRole(ctx context.Context, roleID string) error {
	if err := s.permissions.EnableBuiltInRole(ctx, roleID); err != nil {
		return err
	}
	s.invalidateDisabledCache()
	return nil
}

// DisabledBuiltInRoles returns all currently disabled built-in roles.
func (s *Service) DisabledBuiltInRoles(ctx context.Context) ([]string, error) {
	return s.permissions.DisabledBuiltInRoles(ctx)
}

// RoleDefinitions returns all active role definitions, combining in-memory built-in roles and store custom roles.
func (s *Service) RoleDefinitions(ctx context.Context) ([]Role, error) {
	disabledMap, err := s.getDisabledBuiltInRoles(ctx)
	if err != nil {
		disabledMap = map[string]bool{}
	}

	builtInRoles := s.builtIns.Roles()
	rolesByID := map[string]Role{}
	for _, r := range builtInRoles {
		if disabledMap[r.ID] {
			r.IsDisabled = true
		}
		rolesByID[r.ID] = r
	}

	dbRoles, err := s.permissions.RoleDefinitions(ctx)
	if err == nil {
		for _, r := range dbRoles {
			rolesByID[r.ID] = r
		}
	}

	result := make([]Role, 0, len(rolesByID))
	for _, r := range rolesByID {
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// RoleDefinition retrieves a single role definition by ID.
func (s *Service) RoleDefinition(ctx context.Context, roleID string) (Role, error) {
	if role, ok := s.builtIns.Role(roleID); ok {
		disabledMap, _ := s.getDisabledBuiltInRoles(ctx)
		if disabledMap[roleID] {
			role.IsDisabled = true
		}
		return role, nil
	}
	return s.permissions.RoleDefinition(ctx, roleID)
}

// CreateRole registers a role definition. Built-in roles (prefixed with builtin.) are registered in memory, while custom roles are created in the store.
func (s *Service) CreateRole(ctx context.Context, role Role) error {
	if strings.HasPrefix(role.ID, BuiltInPrefix) {
		return s.builtIns.RegisterRole(role)
	}
	return s.permissions.CreateRole(ctx, role)
}

// AddRoleInheritance declares that parentRoleID inherits all permissions of childRoleID.
func (s *Service) AddRoleInheritance(ctx context.Context, parentRoleID, childRoleID string) error {
	if strings.HasPrefix(parentRoleID, BuiltInPrefix) && strings.HasPrefix(childRoleID, BuiltInPrefix) {
		return s.builtIns.AddRoleInheritance(parentRoleID, childRoleID)
	}
	return s.permissions.AddRoleInheritance(ctx, parentRoleID, childRoleID)
}

// SaveBuiltIns performs idempotent startup seeding for configured synthetic roles and grants.
func (s *Service) SaveBuiltIns(ctx context.Context, grants []Grant) error {
	if err := s.EnsureSyntheticRoles(ctx); err != nil {
		return err
	}

	for _, grant := range grants {
		if grant.OwnerKind != PrincipalRole {
			return fmt.Errorf("save built-ins only supports role-owned grants")
		}
		if err := s.builtIns.AddGrant(grant); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) syntheticRoleIDSet() map[string]bool {
	set := map[string]bool{}
	if s.publicRoleID != "" {
		set[s.publicRoleID] = true
	}
	if s.authenticatedRoleID != "" {
		set[s.authenticatedRoleID] = true
	}
	if s.adminRoleID != "" {
		set[s.adminRoleID] = true
	}

	return set
}

func (s *Service) ensureRoleExists(_ context.Context, role Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	if strings.HasPrefix(role.ID, BuiltInPrefix) {
		return s.builtIns.RegisterRole(role)
	}
	return s.permissions.CreateRole(context.Background(), role)
}

// AddBuiltInRole idempotently registers a system-managed (built-in) role definition and seeds its default permissions in memory.
func (s *Service) AddBuiltInRole(_ context.Context, role Role) error {
	if role.ID == "" {
		return fmt.Errorf("role ID is required")
	}
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}
	if !strings.HasPrefix(role.ID, BuiltInPrefix) {
		role.ID = BuiltInPrefix + role.ID
	}

	role.BuiltIn = true
	if err := s.builtIns.RegisterRole(role); err != nil {
		return fmt.Errorf("failed to register built-in role %s: %w", role.ID, err)
	}

	for _, perm := range role.Permissions {
		grant := Grant{
			OwnerKind:      PrincipalRole,
			OwnerID:        role.ID,
			Effect:         EffectAllow,
			TeamScope:      "*",
			PermissionName: perm,
		}
		if err := s.builtIns.AddGrant(grant); err != nil {
			return fmt.Errorf("failed to seed grant for built-in role %s: %w", role.ID, err)
		}
	}

	return nil
}

// GetStore returns the underlying PermissionStore.
// Direct interaction with the store is generally not recommended as it bypasses built-in role verification and caching.
func (s *Service) GetStore() PermissionStore {
	return s.permissions
}

// UpdateRole updates a role definition. Returns an error if the role is a built-in role.
func (s *Service) UpdateRole(ctx context.Context, role Role) error {
	if strings.HasPrefix(role.ID, BuiltInPrefix) {
		return fmt.Errorf("cannot update built-in role: %s", role.ID)
	}
	return s.permissions.UpdateRole(ctx, role)
}

// DeleteRole deletes a role definition. Returns an error if the role is a built-in role.
func (s *Service) DeleteRole(ctx context.Context, roleID string) error {
	if strings.HasPrefix(roleID, BuiltInPrefix) {
		return fmt.Errorf("cannot delete built-in role: %s", roleID)
	}
	return s.permissions.DeleteRole(ctx, roleID)
}

// RoleAssignmentsForPrincipal retrieves role assignments for the specified principal.
func (s *Service) RoleAssignmentsForPrincipal(ctx context.Context, principal PrincipalRef) ([]RoleAssignment, error) {
	return s.permissions.RoleAssignmentsForPrincipal(ctx, principal)
}

// AssignRole assigns a role to a principal.
func (s *Service) AssignRole(ctx context.Context, principal PrincipalRef, roleID string, bindingValues map[string]any) error {
	return s.permissions.AssignRole(ctx, principal, roleID, bindingValues)
}

// GrantsForPrincipal retrieves active grants for the specified principal.
// If the principal is a built-in role, it fetches from the in-memory built-in registry.
// Otherwise, it queries the database store.
func (s *Service) GrantsForPrincipal(ctx context.Context, principal PrincipalRef) ([]Grant, error) {
	if principal.Kind == PrincipalRole && strings.HasPrefix(principal.ID, BuiltInPrefix) {
		return s.builtIns.GrantsForOwners([]PrincipalRef{principal}, Request{}), nil
	}
	return s.permissions.GrantsForPrincipal(ctx, principal)
}

// GrantsForOwners retrieves active grants for the specified owners, merging in-memory built-in grants and custom grants from the store.
func (s *Service) GrantsForOwners(ctx context.Context, owners []PrincipalRef, req Request) ([]Grant, error) {
	var builtInOwners []PrincipalRef
	var customOwners []PrincipalRef
	for _, owner := range owners {
		if owner.Kind == PrincipalRole && strings.HasPrefix(owner.ID, BuiltInPrefix) {
			builtInOwners = append(builtInOwners, owner)
		} else {
			customOwners = append(customOwners, owner)
		}
	}

	var grants []Grant
	if len(builtInOwners) > 0 {
		grants = append(grants, s.builtIns.GrantsForOwners(builtInOwners, req)...)
	}

	if len(customOwners) > 0 {
		cg, err := s.permissions.GrantsForOwners(ctx, customOwners, req)
		if err != nil {
			return nil, err
		}
		grants = append(grants, cg...)
	}

	return grants, nil
}

// PrincipalsWithGrant retrieves all principal hits containing a grant matching the request criteria.
func (s *Service) PrincipalsWithGrant(ctx context.Context, req Request) ([]PrincipalHit, error) {
	return s.permissions.PrincipalsWithGrant(ctx, req)
}

// ExpandRoles resolves the full transitive closure of inherited roles for the given role IDs, filtering out disabled roles.
func (s *Service) ExpandRoles(ctx context.Context, roleIDs []string) ([]string, error) {
	var builtInIDs []string
	var customIDs []string
	for _, id := range roleIDs {
		if strings.HasPrefix(id, BuiltInPrefix) {
			builtInIDs = append(builtInIDs, id)
		} else {
			customIDs = append(customIDs, id)
		}
	}

	var expanded []string
	if len(customIDs) > 0 {
		dbExpanded, err := s.permissions.ExpandRoles(ctx, customIDs)
		if err != nil {
			return nil, err
		}
		expanded = append(expanded, dbExpanded...)
	}

	if len(builtInIDs) > 0 {
		expanded = append(expanded, builtInIDs...)
	}

	expanded = s.builtIns.ExpandRoles(expanded)

	disabledMap, err := s.getDisabledBuiltInRoles(ctx)
	if err != nil {
		disabledMap = map[string]bool{}
	}

	seen := map[string]bool{}
	var filtered []string
	for _, rID := range expanded {
		if seen[rID] {
			continue
		}
		seen[rID] = true

		if disabledMap[rID] {
			continue
		}
		roleDef, err := s.RoleDefinition(ctx, rID)
		if err == nil && roleDef.IsDisabled {
			continue
		}
		filtered = append(filtered, rID)
	}

	return filtered, nil
}

// DeleteGrantsForOwner deletes all grants for a given principal owner. Returns an error if the owner is a built-in role.
func (s *Service) DeleteGrantsForOwner(ctx context.Context, ownerKind PrincipalKind, ownerID string) error {
	if ownerKind == PrincipalRole && strings.HasPrefix(ownerID, BuiltInPrefix) {
		return fmt.Errorf("cannot delete grants for built-in role: %s", ownerID)
	}
	return s.permissions.DeleteGrantsForOwner(ctx, ownerKind, ownerID)
}

func grantsEquivalent(left, right Grant) bool {
	if left.OwnerKind != right.OwnerKind || left.OwnerID != right.OwnerID {
		return false
	}
	if left.Effect != right.Effect || left.TeamScope != right.TeamScope || left.PermissionName != right.PermissionName {
		return false
	}
	if !sameStringPointer(left.ObjectScope, right.ObjectScope) {
		return false
	}
	if !sameTimePointer(left.ExpiresAt, right.ExpiresAt) {
		return false
	}
	if !sameStringSet(left.RestrictedFields, right.RestrictedFields) {
		return false
	}

	return reflect.DeepEqual(left.VariableSpec, right.VariableSpec)
}

func sameStringPointer(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return *left == *right
}

func sameTimePointer(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Equal(*right)
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	if len(left) == 0 {
		return true
	}

	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)

	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}

	return true
}

func cloneGrantSlice(values []Grant) []Grant {
	if len(values) == 0 {
		return nil
	}

	cloned := make([]Grant, 0, len(values))
	for _, grant := range values {
		copyGrant := grant
		copyGrant.ObjectScope = cloneStringPointer(grant.ObjectScope)
		copyGrant.ExpiresAt = cloneTimePointer(grant.ExpiresAt)
		copyGrant.RestrictedFields = append([]string(nil), grant.RestrictedFields...)
		if grant.VariableSpec != nil {
			copyGrant.VariableSpec = map[string]any{}
			for k, v := range grant.VariableSpec {
				copyGrant.VariableSpec[k] = v
			}
		} else {
			copyGrant.VariableSpec = nil
		}
		cloned = append(cloned, copyGrant)
	}

	return cloned
}

func cloneStringPointer(v *string) *string {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}

func cloneTimePointer(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	copyValue := *v
	return &copyValue
}
