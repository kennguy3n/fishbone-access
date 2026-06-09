package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Sentinel errors. The handler layer maps these to HTTP status codes
// (ErrMembershipNotFound -> 403, ErrLastOwnerProtected -> 409,
// ErrInvalidRole/ErrValidation -> 400, ErrOwnerEscalationForbidden -> 403).
var (
	// ErrMembershipNotFound is returned when the user has no workspace_members
	// row for the workspace. AuthzMiddleware treats it as fail-closed 403.
	ErrMembershipNotFound = errors.New("authz: user is not a member of the workspace")

	// ErrInvalidRole is returned when a role string is not a recognised
	// WorkspaceRole (input validation, or a corrupt stored row).
	ErrInvalidRole = errors.New("authz: invalid workspace role")

	// ErrValidation is returned for missing required inputs (e.g. an empty
	// actor on the HTTP path).
	ErrValidation = errors.New("authz: validation error")

	// ErrLastOwnerProtected is returned when an upsert/delete would remove or
	// demote the workspace's last owner.
	ErrLastOwnerProtected = errors.New("authz: cannot remove or demote the last workspace owner")

	// ErrOwnerEscalationForbidden is returned when a non-owner actor attempts
	// to promote a user to owner or to modify an existing owner.
	ErrOwnerEscalationForbidden = errors.New("authz: only workspace owners can promote members to owner or modify an existing owner")
)

// SystemActor is the audit actor recorded when a trusted-caller path
// (bootstrap, migration, test fixture) mutates membership without an
// authenticated HTTP actor, so the audit row is never written with an empty
// actor.
const SystemActor = "system"

// DefaultCacheTTL balances hot-path cost against operator-change
// responsiveness for the membership cache in production.
const DefaultCacheTTL = 60 * time.Second

// DefaultNegativeCacheTTL is applied to negative (ErrMembershipNotFound) cache
// entries when the service runs with a positive cacheTTL. It is intentionally
// much shorter than the positive TTL so a freshly-added member sees access
// take effect quickly, while still absorbing the dominant DoS vector of
// repeated non-member JWT lookups under adversarial traffic.
const DefaultNegativeCacheTTL = 5 * time.Second

// DefaultMaxCacheEntries bounds the in-memory membership cache so a long-running
// process cannot grow it without limit. JWTs are validated by iam-core before
// reaching us, so keys are real (workspace, user) pairs; at 5k SME tenants the
// live working set is far below this. The cap is the backstop against pathological
// churn (e.g. rotating user IDs in otherwise-valid tokens filling the negative
// cache): an entry holds a role + four small fields, so ~200k entries is well
// under a few tens of MB. Eviction only forces a DB re-read, never a wrong answer.
const DefaultMaxCacheEntries = 200_000

// withRowLock applies SELECT ... FOR UPDATE on Postgres so concurrent
// membership mutations on the same row serialize past the last-owner guard
// instead of racing. No-op on SQLite (the test path serializes writers with a
// single global write lock).
func withRowLock(tx *gorm.DB) *gorm.DB {
	if tx.Dialector != nil && tx.Name() == "postgres" {
		return tx.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return tx
}

// countOtherOwnersLocked returns the number of owner rows in the workspace
// other than excludeUserID, locking those rows FOR UPDATE so concurrent
// demotions/removals of different owners serialize past the last-owner guard.
//
// It deliberately uses a row-returning SELECT (Pluck of user_id) rather than
// COUNT(*): Postgres rejects FOR UPDATE on an aggregate query
// ("FOR UPDATE is not allowed with aggregate functions"), so a locked COUNT
// would error at runtime on the production dialect. Plucking the matched
// owners' ids locks the actual rows and counts them in Go, which serializes
// correctly on Postgres and is a no-op lock on SQLite (test path).
func countOtherOwnersLocked(tx *gorm.DB, workspaceID uuid.UUID, excludeUserID string) (int64, error) {
	var ownerIDs []string
	if err := withRowLock(tx).Model(&models.WorkspaceMember{}).
		Where("workspace_id = ? AND user_id != ? AND role = ?", workspaceID, excludeUserID, string(RoleOwner)).
		Pluck("user_id", &ownerIDs).Error; err != nil {
		return 0, err
	}
	return int64(len(ownerIDs)), nil
}

type membershipCacheKey struct {
	workspaceID uuid.UUID
	userID      string
}

// membershipCacheEntry holds the full row (not just the role) so a cache hit
// can still feed CreatedAt/UpdatedAt to audit emission. notFound is the
// negative-cache sentinel: when true the entry represents a cached
// ErrMembershipNotFound and the role/timestamps are zero values.
type membershipCacheEntry struct {
	role      WorkspaceRole
	createdAt time.Time
	updatedAt time.Time
	expiresAt time.Time
	notFound  bool
}

// Membership is the value object returned by GetMembership. Role is the
// canonical source for permission lookups; timestamps are echoed for audit.
type Membership struct {
	WorkspaceID uuid.UUID
	UserID      string
	Role        WorkspaceRole
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RBACService resolves and mutates workspace memberships. Construct via
// NewRBACService; the zero value's cache mutex is unusable. It is safe for
// concurrent use.
type RBACService struct {
	db               *gorm.DB
	cacheTTL         time.Duration
	negativeCacheTTL time.Duration
	maxCacheEntries  int
	now              func() time.Time // injectable for tests

	mu    sync.RWMutex
	cache map[membershipCacheKey]membershipCacheEntry
}

// NewRBACService returns a wired RBACService. A cacheTTL of 0 disables the
// cache (every call hits the DB) — useful for tests needing deterministic
// invalidation. The negative-cache TTL defaults to DefaultNegativeCacheTTL
// whenever cacheTTL > 0, clamped to never exceed the positive TTL.
func NewRBACService(db *gorm.DB, cacheTTL time.Duration) *RBACService {
	if cacheTTL < 0 {
		cacheTTL = 0
	}
	negTTL := time.Duration(0)
	if cacheTTL > 0 {
		negTTL = DefaultNegativeCacheTTL
		if negTTL > cacheTTL {
			negTTL = cacheTTL
		}
	}
	return &RBACService{
		db:               db,
		cacheTTL:         cacheTTL,
		negativeCacheTTL: negTTL,
		maxCacheEntries:  DefaultMaxCacheEntries,
		now:              time.Now,
		cache:            make(map[membershipCacheKey]membershipCacheEntry),
	}
}

// SetMaxCacheEntries overrides the cache size bound. Test-only escape hatch so a
// test can exercise eviction at a small cap; values <= 0 are ignored.
func (s *RBACService) SetMaxCacheEntries(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	s.maxCacheEntries = n
	s.mu.Unlock()
}

// storeCacheEntry writes entry under the cache lock while bounding the map to
// maxCacheEntries. When inserting a new key would exceed the cap we first sweep
// expired entries (cheap, and the common case since negative entries expire in
// seconds); if the map is still full of live entries we then evict as we scan
// until there is room. Go randomizes map iteration order, so the fallback is a
// crude random eviction. Evicting a live entry only forces a DB re-read on its
// next access — never a wrong answer, since the DB stays the source of truth.
func (s *RBACService) storeCacheEntry(key membershipCacheKey, entry membershipCacheEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.cache[key]; !exists && len(s.cache) >= s.maxCacheEntries {
		now := s.now()
		for k, e := range s.cache {
			if len(s.cache) < s.maxCacheEntries {
				break
			}
			if !e.expiresAt.After(now) {
				delete(s.cache, k)
			}
		}
		for k := range s.cache {
			if len(s.cache) < s.maxCacheEntries {
				break
			}
			delete(s.cache, k)
		}
	}
	s.cache[key] = entry
}

// SetClock overrides the time source. Test-only; production callers leave the
// default time.Now in place. A nil function falls back to time.Now.
func (s *RBACService) SetClock(now func() time.Time) {
	if now == nil {
		s.now = time.Now
		return
	}
	s.now = now
}

// SetNegativeCacheTTL overrides the negative-cache TTL. Test-only escape hatch;
// 0 disables negative caching. Values exceeding the positive cacheTTL clamp to
// it so negatives never outlive positives.
func (s *RBACService) SetNegativeCacheTTL(d time.Duration) {
	if d < 0 {
		d = 0
	}
	if d > s.cacheTTL {
		d = s.cacheTTL
	}
	s.negativeCacheTTL = d
}

// GetMembership returns the membership for (workspaceID, userID) or
// ErrMembershipNotFound. Cache-aware: a non-expired positive entry returns a
// Membership immediately; a non-expired negative entry returns
// ErrMembershipNotFound without a DB query (closing the non-member-JWT DoS
// vector); a miss populates the cache after a DB lookup.
func (s *RBACService) GetMembership(ctx context.Context, workspaceID uuid.UUID, userID string) (*Membership, error) {
	if s == nil {
		return nil, fmt.Errorf("authz: nil service")
	}
	if workspaceID == uuid.Nil || userID == "" {
		return nil, fmt.Errorf("authz: workspaceID and userID are required")
	}

	if s.cacheTTL > 0 {
		key := membershipCacheKey{workspaceID: workspaceID, userID: userID}
		s.mu.RLock()
		entry, ok := s.cache[key]
		s.mu.RUnlock()
		if ok && entry.expiresAt.After(s.now()) {
			if entry.notFound {
				return nil, ErrMembershipNotFound
			}
			return &Membership{
				WorkspaceID: workspaceID,
				UserID:      userID,
				Role:        entry.role,
				CreatedAt:   entry.createdAt,
				UpdatedAt:   entry.updatedAt,
			}, nil
		}
	}

	var row models.WorkspaceMember
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if s.cacheTTL > 0 && s.negativeCacheTTL > 0 {
				key := membershipCacheKey{workspaceID: workspaceID, userID: userID}
				s.storeCacheEntry(key, membershipCacheEntry{
					notFound:  true,
					expiresAt: s.now().Add(s.negativeCacheTTL),
				})
			}
			return nil, ErrMembershipNotFound
		}
		return nil, fmt.Errorf("authz: query workspace_members: %w", err)
	}

	role := WorkspaceRole(row.Role)
	if !role.IsValid() {
		// Defensive: the DB CHECK constraint should reject invalid roles at
		// insert time. If a bad row lands anyway (manual SQL, older schema),
		// fail closed rather than granting an empty permission set silently.
		logger.Errorf(ctx, "authz: workspace_members row has invalid role workspace_id=%s user_id=%s role=%s", workspaceID, userID, row.Role)
		return nil, fmt.Errorf("%w: stored role %q is not recognised", ErrInvalidRole, row.Role)
	}

	if s.cacheTTL > 0 {
		key := membershipCacheKey{workspaceID: workspaceID, userID: userID}
		s.storeCacheEntry(key, membershipCacheEntry{
			role:      role,
			createdAt: row.CreatedAt,
			updatedAt: row.UpdatedAt,
			expiresAt: s.now().Add(s.cacheTTL),
		})
	}

	return &Membership{
		WorkspaceID: row.WorkspaceID,
		UserID:      row.UserID,
		Role:        role,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

// PermissionsForUser returns the PermissionSet the user holds in the workspace.
// Convenience wrapper over GetMembership + PermissionsForRole. Returns an empty
// (non-nil) set on ErrMembershipNotFound so callers can chain .Has(...) safely;
// the error is returned alongside so callers can distinguish "not a member".
func (s *RBACService) PermissionsForUser(ctx context.Context, workspaceID uuid.UUID, userID string) (PermissionSet, error) {
	m, err := s.GetMembership(ctx, workspaceID, userID)
	if err != nil {
		return NewPermissionSet(0), err
	}
	return PermissionsForRole(m.Role), nil
}

// HasPermission is the hot-path single-permission check. Returns
// (false, ErrMembershipNotFound) when the user is not a member, (false, nil)
// when they are a member but the role lacks the permission, and (true, nil) on
// success.
func (s *RBACService) HasPermission(ctx context.Context, workspaceID uuid.UUID, userID string, perm Permission) (bool, error) {
	m, err := s.GetMembership(ctx, workspaceID, userID)
	if err != nil {
		return false, err
	}
	return PermissionsForRole(m.Role).Has(perm), nil
}

// UpsertMember inserts or updates the membership row for (workspaceID, userID)
// with the supplied role. Enforces the "exactly one owner" invariant. This is
// the trusted-caller / bootstrap path (provisioning, migrations, fixtures): it
// does NOT run the actor-role privilege check. HTTP handlers MUST use
// UpsertMemberAs so the privilege check runs atomically with the write.
//
// actorUserID is the audit actor; an empty string (trusted-caller path)
// resolves to SystemActor.
func (s *RBACService) UpsertMember(ctx context.Context, workspaceID uuid.UUID, userID string, role WorkspaceRole, actorUserID string) error {
	return s.upsertMember(ctx, workspaceID, userID, role, "", actorUserID)
}

// UpsertMemberAs is the HTTP-facing variant that enforces the actor-role
// privilege check inside the same transaction as the write. It fails closed
// with ErrOwnerEscalationForbidden when a non-owner attempts to promote any
// user to owner, or to modify an existing owner row. Empty actorRole is
// rejected with ErrInvalidRole and empty actorUserID with ErrValidation — HTTP
// handlers stamp both from the authz context.
func (s *RBACService) UpsertMemberAs(ctx context.Context, workspaceID uuid.UUID, userID string, role, actorRole WorkspaceRole, actorUserID string) error {
	if actorRole == "" {
		return fmt.Errorf("%w: actor role is required for UpsertMemberAs", ErrInvalidRole)
	}
	if actorUserID == "" {
		return fmt.Errorf("%w: actor_user_id is required for UpsertMemberAs", ErrValidation)
	}
	return s.upsertMember(ctx, workspaceID, userID, role, actorRole, actorUserID)
}

// upsertMember is the shared implementation. actorRole == "" disables the
// owner-escalation guard (trusted-caller path); any non-empty actorRole is
// enforced inside the transaction. The last-owner invariant is enforced
// unconditionally.
func (s *RBACService) upsertMember(ctx context.Context, workspaceID uuid.UUID, userID string, role, actorRole WorkspaceRole, actorUserID string) error {
	if s == nil {
		return fmt.Errorf("authz: nil service")
	}
	if workspaceID == uuid.Nil || userID == "" {
		return fmt.Errorf("authz: workspaceID and userID are required")
	}
	if !role.IsValid() {
		return fmt.Errorf("%w: %q", ErrInvalidRole, role)
	}
	if actorRole != "" && !actorRole.IsValid() {
		return fmt.Errorf("%w: actor role %q", ErrInvalidRole, actorRole)
	}

	now := s.now()

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Lock the target row (if any) so a concurrent mutation blocks on
		// commit instead of racing past the guards below.
		var existing models.WorkspaceMember
		err := withRowLock(tx).
			Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
			First(&existing).Error
		isUpdate := !errors.Is(err, gorm.ErrRecordNotFound)
		if isUpdate && err != nil {
			return fmt.Errorf("authz: read existing membership: %w", err)
		}

		// Owner-escalation guard (HTTP path only). Runs after the row is
		// locked so the actor cannot race a promote-to-owner against a
		// concurrent demote-self performed by an owner peer.
		if actorRole != "" && actorRole != RoleOwner {
			if role == RoleOwner {
				return ErrOwnerEscalationForbidden
			}
			if isUpdate && existing.Role == string(RoleOwner) {
				return ErrOwnerEscalationForbidden
			}
		}

		// Last-owner guard: a demote of the current owner is rejected unless
		// another owner remains. The matching owner rows are locked FOR UPDATE
		// so concurrent demotes of other owners serialize and re-read the
		// post-commit owner set.
		if isUpdate && existing.Role == string(RoleOwner) && role != RoleOwner {
			otherOwnerCount, err := countOtherOwnersLocked(tx, workspaceID, userID)
			if err != nil {
				return fmt.Errorf("authz: count other owners: %w", err)
			}
			if otherOwnerCount == 0 {
				return ErrLastOwnerProtected
			}
		}

		if !isUpdate {
			row := models.WorkspaceMember{
				WorkspaceID: workspaceID,
				UserID:      userID,
				Role:        string(role),
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if err := tx.Create(&row).Error; err != nil {
				return fmt.Errorf("authz: insert workspace_members: %w", err)
			}
			return s.appendMemberAudit(ctx, tx, now, workspaceID, userID, "rbac.member.added", "", role, actorUserID)
		}

		if err := tx.Model(&models.WorkspaceMember{}).
			Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
			Updates(map[string]any{"role": string(role), "updated_at": now}).Error; err != nil {
			return fmt.Errorf("authz: update workspace_members: %w", err)
		}
		// Only audit an actual role transition; a no-op re-stamp of the same
		// role must not pollute the audit chain.
		prevRole := WorkspaceRole(existing.Role)
		if prevRole != role {
			return s.appendMemberAudit(ctx, tx, now, workspaceID, userID, "rbac.member.role_changed", prevRole, role, actorUserID)
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.invalidateCache(workspaceID, userID)
	return nil
}

// DeleteMember removes the (workspaceID, userID) row on the trusted-caller path
// (no actor-role privilege check). Enforces the last-owner invariant.
// Idempotent: a delete against a non-member returns nil and emits no audit
// event. actorUserID is the audit actor (empty -> SystemActor). HTTP handlers
// MUST use DeleteMemberAs so the owner-escalation check runs atomically with
// the delete.
func (s *RBACService) DeleteMember(ctx context.Context, workspaceID uuid.UUID, userID, actorUserID string) error {
	return s.deleteMember(ctx, workspaceID, userID, "", actorUserID)
}

// DeleteMemberAs is the HTTP-facing variant that enforces the actor-role
// privilege check inside the same transaction as the delete. It fails closed
// with ErrOwnerEscalationForbidden when a non-owner attempts to remove an
// existing owner — mirroring UpsertMemberAs so an admin cannot escalate by
// deleting an owner. Empty actorRole is rejected with ErrInvalidRole and empty
// actorUserID with ErrValidation — HTTP handlers stamp both from the authz
// context.
func (s *RBACService) DeleteMemberAs(ctx context.Context, workspaceID uuid.UUID, userID string, actorRole WorkspaceRole, actorUserID string) error {
	if actorRole == "" {
		return fmt.Errorf("%w: actor role is required for DeleteMemberAs", ErrInvalidRole)
	}
	if actorUserID == "" {
		return fmt.Errorf("%w: actor_user_id is required for DeleteMemberAs", ErrValidation)
	}
	return s.deleteMember(ctx, workspaceID, userID, actorRole, actorUserID)
}

// deleteMember is the shared implementation. actorRole == "" disables the
// owner-escalation guard (trusted-caller path); any non-empty actorRole is
// enforced inside the transaction. The last-owner invariant is enforced
// unconditionally.
func (s *RBACService) deleteMember(ctx context.Context, workspaceID uuid.UUID, userID string, actorRole WorkspaceRole, actorUserID string) error {
	if s == nil {
		return fmt.Errorf("authz: nil service")
	}
	if workspaceID == uuid.Nil || userID == "" {
		return fmt.Errorf("authz: workspaceID and userID are required")
	}
	if actorRole != "" && !actorRole.IsValid() {
		return fmt.Errorf("%w: actor role %q", ErrInvalidRole, actorRole)
	}

	now := s.now()

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing models.WorkspaceMember
		err := withRowLock(tx).
			Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
			First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // idempotent
		}
		if err != nil {
			return fmt.Errorf("authz: read existing membership: %w", err)
		}

		// Owner-escalation guard (HTTP path only): only an owner may remove an
		// existing owner. Runs after the row is locked so a non-owner cannot
		// race the removal of an owner peer.
		if actorRole != "" && actorRole != RoleOwner && existing.Role == string(RoleOwner) {
			return ErrOwnerEscalationForbidden
		}

		if existing.Role == string(RoleOwner) {
			otherOwnerCount, err := countOtherOwnersLocked(tx, workspaceID, userID)
			if err != nil {
				return fmt.Errorf("authz: count other owners: %w", err)
			}
			if otherOwnerCount == 0 {
				return ErrLastOwnerProtected
			}
		}

		if err := tx.Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
			Delete(&models.WorkspaceMember{}).Error; err != nil {
			return fmt.Errorf("authz: delete workspace_members: %w", err)
		}
		return s.appendMemberAudit(ctx, tx, now, workspaceID, userID, "rbac.member.removed", WorkspaceRole(existing.Role), "", actorUserID)
	})
	if err != nil {
		return err
	}

	s.invalidateCache(workspaceID, userID)
	return nil
}

// ListMembers returns every membership in the workspace ordered by join time.
func (s *RBACService) ListMembers(ctx context.Context, workspaceID uuid.UUID) ([]Membership, error) {
	if s == nil {
		return nil, fmt.Errorf("authz: nil service")
	}
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("authz: workspaceID is required")
	}
	var rows []models.WorkspaceMember
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("authz: list workspace_members: %w", err)
	}
	out := make([]Membership, 0, len(rows))
	for _, r := range rows {
		out = append(out, Membership{
			WorkspaceID: r.WorkspaceID,
			UserID:      r.UserID,
			Role:        WorkspaceRole(r.Role),
			CreatedAt:   r.CreatedAt,
			UpdatedAt:   r.UpdatedAt,
		})
	}
	return out, nil
}

// invalidateCache drops the cached entry (positive or negative) for
// (workspaceID, userID) after a mutation so the next GetMembership reflects the
// change without waiting for TTL expiry.
func (s *RBACService) invalidateCache(workspaceID uuid.UUID, userID string) {
	if s.cacheTTL <= 0 {
		return
	}
	s.mu.Lock()
	delete(s.cache, membershipCacheKey{workspaceID: workspaceID, userID: userID})
	s.mu.Unlock()
}

// appendMemberAudit records a membership mutation into the workspace's
// tamper-evident audit hash chain (the same audit_events chain the lifecycle
// services use), inside the supplied transaction so the membership change and
// its audit row commit atomically.
func (s *RBACService) appendMemberAudit(ctx context.Context, tx *gorm.DB, now time.Time, workspaceID uuid.UUID, targetUserID, action string, oldRole, newRole WorkspaceRole, actorUserID string) error {
	actor := actorUserID
	if actor == "" {
		actor = SystemActor
	}
	meta, err := json.Marshal(map[string]string{
		"target_user_id": targetUserID,
		"old_role":       string(oldRole),
		"new_role":       string(newRole),
	})
	if err != nil {
		return fmt.Errorf("authz: marshal audit metadata: %w", err)
	}
	return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      action,
		TargetRef:   targetUserID,
		Metadata:    datatypes.JSON(meta),
	})
}
