package tenancy

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Config tunes the Service. It mirrors the subset of config.TenancyConfig the
// runtime logic needs, decoupling the package from the config struct so it can
// be unit-tested without the whole loader.
type Config struct {
	// Enabled gates hibernation. When false, ShouldRunPeriodic always returns
	// true (no tenant is ever treated as dormant) while activity is still
	// recorded — so the optimisation can be turned off without losing data.
	Enabled bool
	// IdleThreshold is how long without activity before a tenant is dormant.
	IdleThreshold time.Duration
	// DefaultTier is the budget tier for tenants without an explicit budget row.
	DefaultTier string
}

// Service is the high-level tenancy API: the dormancy gate, the activity sink,
// the reconcile entry point, and budget resolution. It is the type production
// wires and the type tests exercise.
type Service struct {
	store *Store
	cfg   Config
}

// NewService builds a Service over db. It applies safe fallbacks so a partially
// configured Config still behaves sensibly (a non-positive idle threshold falls
// back to 14 days; an empty default tier falls back to trial).
func NewService(db *gorm.DB, cfg Config) *Service {
	if cfg.IdleThreshold <= 0 {
		cfg.IdleThreshold = 14 * 24 * time.Hour
	}
	if cfg.DefaultTier == "" {
		cfg.DefaultTier = TierTrial
	}
	return &Service{store: NewStore(db), cfg: cfg}
}

// WithClock returns a copy of the Service whose store uses clk (tests only).
func (s *Service) WithClock(clk func() time.Time) *Service {
	cp := *s
	cp.store = s.store.WithClock(clk)
	return &cp
}

// Store exposes the underlying store for migration/seed/admin operations
// (e.g. cmd wiring calling Migrate, or an admin endpoint setting a budget).
func (s *Service) Store() *Store { return s.store }

// Config returns the effective (fallback-applied) configuration.
func (s *Service) Config() Config { return s.cfg }

// ShouldRunPeriodic implements HibernationGate. When hibernation is disabled it
// short-circuits to true (no DB read). Otherwise it reads the persisted state
// and returns false only for a confidently-dormant tenant; a missing row or an
// error yields true (fail-open).
func (s *Service) ShouldRunPeriodic(ctx context.Context, workspaceID uuid.UUID) (bool, error) {
	if !s.cfg.Enabled {
		return true, nil
	}
	dormant, err := s.store.IsDormant(ctx, workspaceID)
	if err != nil {
		// Fail open: never let a classification read error stop real work.
		return true, err
	}
	return !dormant, nil
}

// RecordActivity records real activity for a tenant and lazily wakes it if it
// was dormant. Returns whether THIS call performed the wake (so a caller can
// emit a one-shot wake event). Activity is recorded even when hibernation is
// disabled, so toggling the feature on later has accurate history to classify.
func (s *Service) RecordActivity(ctx context.Context, workspaceID uuid.UUID, kind string) (woke bool, err error) {
	return s.store.RecordActivity(ctx, workspaceID, kind)
}

// Reconcile runs one dormancy sweep using the configured idle threshold.
func (s *Service) Reconcile(ctx context.Context) (ReconcileResult, error) {
	return s.store.Reconcile(ctx, s.cfg.IdleThreshold)
}

// BudgetFor resolves the effective resource budget for a tenant.
func (s *Service) BudgetFor(ctx context.Context, workspaceID uuid.UUID) (Budget, error) {
	return s.store.BudgetFor(ctx, workspaceID, s.cfg.DefaultTier)
}
