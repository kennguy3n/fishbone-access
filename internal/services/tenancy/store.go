package tenancy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Store is the GORM-backed persistence for tenant activity + budgets. It honours
// the same backend contract as the rest of the control plane: it works
// identically on the Postgres production path and the SQLite test path, and
// every method is workspace-scoped (no unscoped mutation is exposed).
type Store struct {
	db    *gorm.DB
	clock func() time.Time
}

// NewStore wraps a *gorm.DB. clock defaults to time.Now; tests inject a fake.
func NewStore(db *gorm.DB) *Store {
	return &Store{db: db, clock: time.Now}
}

// WithClock returns a copy of the store using clk for all timestamps. Used by
// tests to drive the idle threshold deterministically.
func (s *Store) WithClock(clk func() time.Time) *Store {
	cp := *s
	cp.clock = clk
	return &cp
}

func (s *Store) now() time.Time {
	if s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

// Migrate auto-migrates the tenancy tables. It is for the SQLite test/dev path
// only; production schema evolution goes through the ordered SQL migrations
// (0018/0019), which this mirrors. Kept here (not in models.All) so the tenancy
// schema stays owned by this package.
func (s *Store) Migrate() error {
	if err := s.db.AutoMigrate(&TenantActivity{}, &TenantResourceBudget{}); err != nil {
		return fmt.Errorf("tenancy: auto-migrate: %w", err)
	}
	return nil
}

// RecordActivity marks the workspace as having had real activity now. It is
// idempotent and safe under concurrency:
//
//   - It upserts the activity row (insert on first sight, else refresh
//     last_activity_at + kind) WITHOUT touching state, so a steady stream of
//     activity does not churn the state column.
//   - It then performs a single conditional transition dormant→active. The
//     RowsAffected of that UPDATE tells us whether THIS call woke the tenant,
//     which it reports as woke — letting callers log/emit a wake event exactly
//     once rather than on every subsequent request.
//
// Both statements are workspace-scoped and use parameter binding, so this is a
// constant-cost pair of indexed writes regardless of fleet size.
func (s *Store) RecordActivity(ctx context.Context, workspaceID uuid.UUID, kind string) (woke bool, err error) {
	if workspaceID == uuid.Nil {
		return false, errors.New("tenancy: RecordActivity: empty workspace id")
	}
	if kind == "" {
		kind = KindUnknown
	}
	now := s.now()
	row := TenantActivity{
		WorkspaceID:      workspaceID,
		LastActivityAt:   now,
		LastActivityKind: kind,
		State:            StateActive,
		StateChangedAt:   now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	// Upsert the freshness fields only. On conflict we deliberately do NOT write
	// state/state_changed_at here so the wake transition below stays the single
	// authority for state changes (and reports the transition accurately).
	if err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"last_activity_at":   now,
				"last_activity_kind": kind,
				"updated_at":         now,
			}),
		}).
		Create(&row).Error; err != nil {
		return false, fmt.Errorf("tenancy: record activity: %w", err)
	}

	res := s.db.WithContext(ctx).
		Model(&TenantActivity{}).
		Where("workspace_id = ? AND state = ?", workspaceID, StateDormant).
		Updates(map[string]any{
			"state":            StateActive,
			"woken_at":         now,
			"state_changed_at": now,
			"updated_at":       now,
		})
	if res.Error != nil {
		return false, fmt.Errorf("tenancy: wake transition: %w", res.Error)
	}
	return res.RowsAffected > 0, nil
}

// GetActivity returns the activity row for a workspace, or gorm.ErrRecordNotFound
// when none exists yet.
func (s *Store) GetActivity(ctx context.Context, workspaceID uuid.UUID) (TenantActivity, error) {
	var row TenantActivity
	err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		First(&row).Error
	if err != nil {
		return TenantActivity{}, err
	}
	return row, nil
}

// IsDormant reports whether the workspace is currently classified dormant. A
// missing row (never classified) reports false — fail-open, so the gate never
// hibernates a tenant the sweep has not yet seen.
func (s *Store) IsDormant(ctx context.Context, workspaceID uuid.UUID) (bool, error) {
	row, err := s.GetActivity(ctx, workspaceID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.Dormant(), nil
}

// CountDormant returns the number of workspaces currently classified dormant.
// It is a single indexed aggregate over the state column (no per-tenant fan-out
// and no tenant data returned), so it is cheap to call once per reconcile sweep
// to publish the fleet-wide dormant gauge. It needs no RLS/tenant context: it
// is an unscoped COUNT of an operational classification column, not a read of
// any tenant's data.
func (s *Store) CountDormant(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.WithContext(ctx).
		Model(&TenantActivity{}).
		Where("state = ?", StateDormant).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("tenancy: count dormant: %w", err)
	}
	return n, nil
}

// ReconcileResult reports what a sweep changed, for logging/metrics.
type ReconcileResult struct {
	// Seeded is the number of workspaces that gained an activity row this sweep
	// (lazy backfill for tenants provisioned before the row existed).
	Seeded int64
	// Hibernated / Woken are the active→dormant and dormant→active transitions
	// the sweep applied.
	Hibernated int64
	Woken      int64
}

// Reconcile (re)classifies every workspace against idleThreshold in three
// set-based statements, so the cost is O(changed rows), not O(tenants) round
// trips — the property that keeps a 5,000-tenant sweep cheap:
//
//  1. Seed: backfill an ACTIVE row for any live workspace lacking one, using
//     the workspace's creation time as the activity proxy. Classification is
//     left to step 2 — a trial provisioned long ago and never touched is seeded
//     active here and immediately hibernated below, because its proxy activity
//     (created_at) already predates the cutoff.
//  2. Hibernate: active rows whose last activity predates the cutoff → dormant.
//     This catches both long-running tenants that went idle AND the just-seeded
//     stale trials, so the seed needs no per-row CASE.
//  3. Wake: dormant rows whose last activity is at/after the cutoff → active
//     (a backstop; RecordActivity is the primary wake path).
//
// The three statements run in one transaction so a concurrent gate read can
// never observe a stale trial in the transient active state between seed and
// hibernate. The cutoff is computed in Go and bound as a parameter so the SQL
// is identical (and correctly typed) on Postgres and SQLite — no in-SQL CASE on
// a bound timestamp, which Postgres would type as text. The seed uses ON
// CONFLICT DO NOTHING so concurrent reconcilers on multiple replicas cannot
// collide.
func (s *Store) Reconcile(ctx context.Context, idleThreshold time.Duration) (ReconcileResult, error) {
	if idleThreshold <= 0 {
		return ReconcileResult{}, fmt.Errorf("tenancy: reconcile: idle threshold must be positive, got %s", idleThreshold)
	}
	now := s.now()
	cutoff := now.Add(-idleThreshold)
	var out ReconcileResult

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. Seed missing rows from the workspaces table as active; step 2
		// classifies. last_activity_at uses the workspace creation time as the
		// proxy for "never touched".
		seed := tx.Exec(`
INSERT INTO tenant_activity
  (workspace_id, last_activity_at, last_activity_kind, state, state_changed_at, created_at, updated_at)
SELECT w.id, w.created_at, ?, ?, ?, ?, ?
FROM workspaces w
LEFT JOIN tenant_activity ta ON ta.workspace_id = w.id
WHERE ta.workspace_id IS NULL AND w.deleted_at IS NULL
ON CONFLICT (workspace_id) DO NOTHING`,
			KindProvisioned, StateActive, now, now, now,
		)
		if seed.Error != nil {
			return fmt.Errorf("tenancy: reconcile seed: %w", seed.Error)
		}
		out.Seeded = seed.RowsAffected

		// 2. Hibernate idle active tenants (including just-seeded stale trials).
		hib := tx.Exec(`
UPDATE tenant_activity
   SET state = ?, hibernated_at = ?, state_changed_at = ?, updated_at = ?
 WHERE state = ? AND last_activity_at < ?`,
			StateDormant, now, now, now, StateActive, cutoff,
		)
		if hib.Error != nil {
			return fmt.Errorf("tenancy: reconcile hibernate: %w", hib.Error)
		}
		out.Hibernated = hib.RowsAffected

		// 3. Wake dormant tenants whose recorded activity has caught up.
		wake := tx.Exec(`
UPDATE tenant_activity
   SET state = ?, woken_at = ?, state_changed_at = ?, updated_at = ?
 WHERE state = ? AND last_activity_at >= ?`,
			StateActive, now, now, now, StateDormant, cutoff,
		)
		if wake.Error != nil {
			return fmt.Errorf("tenancy: reconcile wake: %w", wake.Error)
		}
		out.Woken = wake.RowsAffected
		return nil
	})
	if err != nil {
		return ReconcileResult{}, err
	}
	return out, nil
}

// BudgetFor resolves the effective resource budget for a workspace: the
// per-workspace override row applied over its tier defaults, or the
// defaultTier's defaults when no row exists. A missing row is the common case
// (most tenants take their tier default), so it is not an error.
func (s *Store) BudgetFor(ctx context.Context, workspaceID uuid.UUID, defaultTier string) (Budget, error) {
	var row TenantResourceBudget
	err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return TierBudget(defaultTier), nil
	}
	if err != nil {
		return Budget{}, fmt.Errorf("tenancy: budget lookup: %w", err)
	}
	return resolveBudget(row), nil
}

// SetBudget upserts a per-workspace budget override. tier is normalized; a zero
// cap means "inherit the tier default" at resolve time.
func (s *Store) SetBudget(ctx context.Context, b TenantResourceBudget) error {
	if b.WorkspaceID == uuid.Nil {
		return errors.New("tenancy: SetBudget: empty workspace id")
	}
	now := s.now()
	b.Tier = normalizeTier(b.Tier)
	b.UpdatedAt = now
	if b.CreatedAt.IsZero() {
		b.CreatedAt = now
	}
	if err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"tier":                       b.Tier,
				"max_concurrent_syncs":       b.MaxConcurrentSyncs,
				"max_periodic_jobs_per_hour": b.MaxPeriodicJobsPerHour,
				"fair_share_weight":          b.FairShareWeight,
				"updated_at":                 now,
			}),
		}).
		Create(&b).Error; err != nil {
		return fmt.Errorf("tenancy: set budget: %w", err)
	}
	return nil
}
