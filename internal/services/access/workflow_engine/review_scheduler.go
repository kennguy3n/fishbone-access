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

// Run blocks, enqueuing a sweep for every workspace once per Interval until ctx
// is cancelled. It runs one sweep round immediately on start so a freshly
// deployed engine does not wait a full interval for the first certification.
func (s *ReviewScheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	// Honour an already-cancelled context before the immediate sweep so a
	// shutdown that races start-up enqueues no work ("no work after
	// cancellation"), rather than firing one best-effort round on the way down.
	if err := ctx.Err(); err != nil {
		return err
	}
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
		if _, err := s.engine.ScheduleReviewSweep(ctx, id, name, s.cfg.Actor, s.cfg.WorkspaceAITier); err != nil {
			logger.Errorf(ctx, "workflow_engine: review scheduler: enqueue sweep for workspace %s: %v", id, err)
			continue
		}
	}
}
