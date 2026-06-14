package workflow_engine

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// workspaceLister enumerates the workspaces a scheduled sweep should cover.
type workspaceLister interface {
	WorkspaceIDs(ctx context.Context) ([]uuid.UUID, error)
}

// sweepScheduler is the slice of the engine the review scheduler needs.
type sweepScheduler interface {
	ScheduleReviewSweep(ctx context.Context, workspaceID uuid.UUID, campaignName, actor, workspaceAITier string) (string, error)
}

// hibernationGate decides whether a tenant's PERIODIC work should run now. The
// scheduler consults it before enqueuing each workspace's review sweep and is
// fail-open by contract (never-classified or any error → run). Declared locally
// (the tenancy.Service satisfies it) so this package needs no tenancy import.
type hibernationGate interface {
	ShouldRunPeriodic(ctx context.Context, workspaceID uuid.UUID) (bool, error)
}

// GormWorkspaceLister lists workspace ids from the workspaces table.
type GormWorkspaceLister struct {
	db *gorm.DB
}

// NewGormWorkspaceLister builds a lister over the given handle.
func NewGormWorkspaceLister(db *gorm.DB) *GormWorkspaceLister {
	return &GormWorkspaceLister{db: db}
}

// WorkspaceIDs returns every workspace id.
func (l *GormWorkspaceLister) WorkspaceIDs(ctx context.Context) ([]uuid.UUID, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("workflow_engine: GormWorkspaceLister not initialised")
	}
	var ids []uuid.UUID
	if err := l.db.WithContext(ctx).Model(&models.Workspace{}).Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("workflow_engine: list workspaces: %w", err)
	}
	return ids, nil
}

// ReviewSchedulerConfig tunes the periodic certification scheduler.
type ReviewSchedulerConfig struct {
	// Interval is how often a certification sweep is enqueued per workspace.
	// Defaults to 24h. The sweep itself is executed asynchronously by the
	// worker, so this only controls cadence, not duration.
	Interval time.Duration
	// WorkspaceAITier selects the LLM tier for the AI review-automation skill.
	WorkspaceAITier string
	// Actor is recorded as the campaign initiator.
	Actor string
}

func (c ReviewSchedulerConfig) withDefaults() ReviewSchedulerConfig {
	if c.Interval <= 0 {
		c.Interval = 24 * time.Hour
	}
	if c.Actor == "" {
		c.Actor = "workflow-engine"
	}
	return c
}

// ReviewScheduler periodically enqueues an access-certification sweep for every
// workspace. It only ENQUEUES work (through the engine, onto the persisted
// queue); the worker executes the sweeps, so a scheduler restart never loses an
// in-flight campaign and two scheduler replicas at worst enqueue duplicate
// sweeps (each sweep is a self-contained campaign, harmless if doubled).
type ReviewScheduler struct {
	engine sweepScheduler
	lister workspaceLister
	cfg    ReviewSchedulerConfig
	now    func() time.Time

	// gate defers a workspace's periodic review sweep when it is confidently
	// dormant. nil means "no gate" (every workspace is swept) so a scheduler
	// built without hibernation degrades to the pre-feature behaviour.
	gate hibernationGate
	// onSkipDormant, when non-nil, counts one review sweep skipped as dormant
	// (the aggregate scale-to-zero metric). nil-able observer seam so this
	// package needs no observability dependency.
	onSkipDormant func()
}

// NewReviewScheduler wires the scheduler. engine and lister are required.
func NewReviewScheduler(engine sweepScheduler, lister workspaceLister, cfg ReviewSchedulerConfig) (*ReviewScheduler, error) {
	if engine == nil {
		return nil, fmt.Errorf("workflow_engine: ReviewScheduler needs an engine")
	}
	if lister == nil {
		return nil, fmt.Errorf("workflow_engine: ReviewScheduler needs a workspace lister")
	}
	return &ReviewScheduler{engine: engine, lister: lister, cfg: cfg.withDefaults(), now: time.Now}, nil
}

// WithHibernationGate attaches the dormancy gate (and an optional skip observer)
// used to defer the periodic review sweep for hibernated workspaces. A nil gate
// is accepted and leaves the scheduler ungated (every workspace is swept).
// Returns the scheduler for chaining at the call site.
func (s *ReviewScheduler) WithHibernationGate(gate hibernationGate, onSkipDormant func()) *ReviewScheduler {
	s.gate = gate
	s.onSkipDormant = onSkipDormant
	return s
}

// Run blocks, enqueuing a sweep for every workspace once per Interval until ctx
// is cancelled. It runs one sweep round immediately on start so a freshly
// deployed engine does not wait a full interval for the first certification.
func (s *ReviewScheduler) Run(ctx context.Context) error {
	// Honour an already-cancelled context before allocating the ticker or
	// running the immediate sweep so a shutdown that races start-up enqueues no
	// work ("no work after cancellation"), rather than firing one best-effort
	// round on the way down.
	if err := ctx.Err(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	s.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce enqueues a sweep per workspace, logging and continuing past a failure
// for any single workspace so one bad workspace cannot starve the rest.
func (s *ReviewScheduler) runOnce(ctx context.Context) {
	ids, err := s.lister.WorkspaceIDs(ctx)
	if err != nil {
		logger.Errorf(ctx, "workflow_engine: review scheduler: list workspaces: %v", err)
		return
	}
	name := fmt.Sprintf("scheduled-review-%s", s.now().UTC().Format("2006-01-02"))
	for _, id := range ids {
		// Hibernation gate (scale-to-zero): defer the periodic certification
		// sweep for a confidently-dormant workspace. Fail-open — a dormant
		// classification is the ONLY thing that skips a workspace; an
		// unclassified tenant or any gate error still enqueues its sweep.
		if !s.shouldSweep(ctx, id) {
			if s.onSkipDormant != nil {
				s.onSkipDormant()
			}
			continue
		}
		if _, err := s.engine.ScheduleReviewSweep(ctx, id, name, s.cfg.Actor, s.cfg.WorkspaceAITier); err != nil {
			logger.Errorf(ctx, "workflow_engine: review scheduler: enqueue sweep for workspace %s: %v", id, err)
			continue
		}
	}
}

// shouldSweep applies the hibernation gate FAIL-OPEN: false (defer the sweep)
// ONLY when a gate is wired and confidently reports the workspace dormant. A nil
// gate, an unclassified tenant, or any gate error all yield true (enqueue).
//
// The gate read is a workspace-scoped primary-key lookup that binds the tenant
// explicitly and returns no tenant data, so it is correct under the worker's
// permissive (non-request-scoped) RLS context and cannot widen isolation.
func (s *ReviewScheduler) shouldSweep(ctx context.Context, workspaceID uuid.UUID) bool {
	if s.gate == nil {
		return true
	}
	run, err := s.gate.ShouldRunPeriodic(ctx, workspaceID)
	if err != nil {
		return true // fail open: never defer a real sweep on a classification error
	}
	return run
}
