package usage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Store is the GORM-backed persistence for the tenant_usage rollup. It honours
// the same backend contract as the rest of the control plane: it works
// identically on the Postgres production path and the SQLite test path, and the
// read method is workspace-scoped (the additive write is workspace-keyed per
// row but intentionally cross-tenant, since it runs from the flush worker —
// see AddUsage).
type Store struct {
	db    *gorm.DB
	clock func() time.Time
}

// NewStore wraps a *gorm.DB. clock defaults to time.Now; tests inject a fake to
// drive the billing period deterministically.
func NewStore(db *gorm.DB) *Store {
	return &Store{db: db, clock: time.Now}
}

// WithClock returns a copy of the store using clk for all timestamps.
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

// Migrate auto-migrates the usage table. It is for the SQLite test/dev path
// only; production schema evolution goes through the ordered SQL migrations
// (0025_tenant_usage.sql), which this mirrors. Kept here (not in models.All)
// so the usage schema stays owned by this package, exactly as tenancy does.
func (s *Store) Migrate() error {
	if err := s.db.AutoMigrate(&TenantUsage{}); err != nil {
		return fmt.Errorf("usage: auto-migrate: %w", err)
	}
	return nil
}

var _ Sink = (*Store)(nil)

// Reader is the read side of the rollup as the usage HTTP handler sees it:
// fetch the calling tenant's current-period usage. Defined as an interface
// (satisfied by *Store) so the handler is decoupled from GORM and testable with
// a fake.
type Reader interface {
	GetCurrentUsage(ctx context.Context, workspaceID uuid.UUID) ([]TenantUsage, error)
}

var _ Reader = (*Store)(nil)

// AddUsage applies a batch of deltas with an ADDITIVE UPSERT inside a single
// transaction: each row inserts on first sight, else adds its delta to the
// existing count (count = count + excluded.count). The additive (not
// last-writer-wins) update is what makes the per-replica posture correct — N
// ztna-api replicas each flush their own deltas and the counts SUM into one row
// rather than clobbering each other.
//
// The whole batch commits atomically, so a failure applies nothing — which is
// the contract the aggregator relies on to merge a failed batch back and retry
// it without double counting.
//
// It is deliberately NOT workspace-scoped to the caller's tenant: the flush
// worker runs with no RLS workspace on its context (the unscoped/worker
// posture), so the tenant_isolation policy on tenant_usage is permissive for it
// and it may UPSERT rows for every active workspace in one batch. The read path
// (GetCurrentUsage) IS scoped, so one tenant can never read another's usage.
func (s *Store) AddUsage(ctx context.Context, deltas []Delta) error {
	if len(deltas) == 0 {
		return nil
	}
	now := s.now()
	rows := make([]TenantUsage, 0, len(deltas))
	for _, d := range deltas {
		if d.WorkspaceID == uuid.Nil || d.Period == "" || d.Metric == "" || d.Count <= 0 {
			// Skip malformed deltas rather than poisoning the batch; the
			// aggregator never produces these, but a defensive skip keeps one
			// bad caller from failing every tenant's flush.
			continue
		}
		rows = append(rows, TenantUsage{
			WorkspaceID: d.WorkspaceID,
			Period:      d.Period,
			Metric:      d.Metric,
			Count:       d.Count,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}, {Name: "period"}, {Name: "metric"}},
			DoUpdates: clause.Assignments(map[string]any{
				"count":      gorm.Expr("tenant_usage.count + excluded.count"),
				"updated_at": now,
			}),
		}).
		Create(&rows).Error
	if err != nil {
		return fmt.Errorf("usage: add usage (%d rows): %w", len(rows), err)
	}
	return nil
}

// GetCurrentUsage returns the workspace's usage rows for the current billing
// period, ordered by metric for a stable response. An empty slice (not an
// error) means the tenant has no recorded usage this period yet. The query is
// explicitly workspace-scoped (the primary isolation mechanism); RLS on
// tenant_usage is the database-tier backstop on the same request connection.
func (s *Store) GetCurrentUsage(ctx context.Context, workspaceID uuid.UUID) ([]TenantUsage, error) {
	return s.GetUsage(ctx, workspaceID, PeriodOf(s.now()))
}

// GetUsage returns the workspace's usage rows for a specific period.
func (s *Store) GetUsage(ctx context.Context, workspaceID uuid.UUID, period string) ([]TenantUsage, error) {
	if workspaceID == uuid.Nil {
		return nil, errors.New("usage: GetUsage: empty workspace id")
	}
	var rows []TenantUsage
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND period = ?", workspaceID, period).
		Order("metric ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("usage: get usage workspace_id=%s period=%s: %w", workspaceID, period, err)
	}
	return rows, nil
}
