package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Store is the plan-assignment persistence for billing, backed by GORM over the
// shared control-plane pool. It mirrors tenancy.Store's budget surface: a
// per-workspace row holding only explicit overrides, resolved against the
// in-code plan defaults so an un-assigned tenant takes the default plan without
// a row.
type Store struct {
	db  *gorm.DB
	now func() time.Time
}

// NewStore wires a Store over db. now defaults to time.Now; tests inject a fixed
// clock for deterministic created/updated timestamps.
func NewStore(db *gorm.DB) *Store {
	return &Store{db: db, now: time.Now}
}

// Migrate auto-migrates the TenantPlan model for the SQLite test/dev path. The
// production schema is applied by 0026_tenant_plan.sql; this keeps the GORM and
// SQL definitions in lock-step the same way usage.Store.Migrate does.
func (s *Store) Migrate() error {
	if err := s.db.AutoMigrate(&TenantPlan{}); err != nil {
		return fmt.Errorf("billing: auto-migrate: %w", err)
	}
	return nil
}

// PlanFor resolves the effective plan for a workspace: the per-workspace row's
// non-zero overrides applied over its plan default, or the default plan when no
// row exists. A missing row is the common case (most tenants take their plan
// default), so it is NOT an error — it returns the default plan. The query is
// explicitly workspace-scoped (the primary isolation mechanism); RLS on
// tenant_plan is the database-tier backstop on the same request connection.
func (s *Store) PlanFor(ctx context.Context, workspaceID uuid.UUID) (Plan, error) {
	if workspaceID == uuid.Nil {
		return Plan{}, errors.New("billing: PlanFor: empty workspace id")
	}
	var row TenantPlan
	err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return defaultPlan(), nil
	}
	if err != nil {
		return Plan{}, fmt.Errorf("billing: plan lookup: %w", err)
	}
	return resolvePlan(row), nil
}

// SetPlan upserts a per-workspace plan assignment. The plan tier is normalized
// (an unknown value coerces to the default tier) and negative overrides are
// clamped to zero ("inherit the plan default"), so a malformed write can never
// persist a value that resolvePlan would misinterpret. The write runs on the
// caller's request connection, so RLS scopes it to the caller's workspace.
func (s *Store) SetPlan(ctx context.Context, p TenantPlan) error {
	if p.WorkspaceID == uuid.Nil {
		return errors.New("billing: SetPlan: empty workspace id")
	}
	now := s.now()
	p.Plan = NormalizePlan(p.Plan)
	if p.APIRequestsIncluded < 0 {
		p.APIRequestsIncluded = 0
	}
	if p.APIRequestsHardCap < 0 {
		p.APIRequestsHardCap = 0
	}
	p.UpdatedAt = now
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"plan":                  p.Plan,
				"api_requests_included": p.APIRequestsIncluded,
				"api_requests_hard_cap": p.APIRequestsHardCap,
				"updated_at":            now,
			}),
		}).
		Create(&p).Error; err != nil {
		return fmt.Errorf("billing: set plan: %w", err)
	}
	return nil
}
