package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
)

// WorkspaceLister enumerates the workspaces the periodic sweep covers. The
// workflow engine's GormWorkspaceLister satisfies it; declared here so this
// package needs no dependency on that package (wiring points one way,
// main → discovery).
type WorkspaceLister interface {
	WorkspaceIDs(ctx context.Context) ([]uuid.UUID, error)
}

// HibernationGate decides whether a tenant's PERIODIC work should run now. It is
// fail-open by contract (an unclassified tenant or any error → run). The
// tenancy.Service satisfies it; declared locally so this package needs no
// tenancy import.
type HibernationGate interface {
	ShouldRunPeriodic(ctx context.Context, workspaceID uuid.UUID) (bool, error)
}

// Sweeper runs the periodic, fail-open auto-onboarding sweep in the workflow
// engine. Each round it asks the engine to re-enumerate connector inventory and
// evaluate the auto-onboarding policy for every ACTIVE workspace. A workspace
// with no enabled policy is a cheap no-op (the engine returns immediately), so
// the round stays negligible across a 5k-tenant fleet; a confidently-dormant
// workspace is skipped entirely via the hibernation gate (scale-to-zero), and
// one workspace's failure never starves the rest.
type Sweeper struct {
	engine *Engine
	lister WorkspaceLister
	cfg    Config

	gate          HibernationGate
	onSkipDormant func()

	// runner, when set, routes per-workspace sweeps through the shared tenancy
	// fair-scheduler (see WithPeriodicRunner): it owns the hibernation gate and
	// the per-tenant/global concurrency budgets, so under fleet load a sweep
	// round shares the global ceiling with the other periodic sweeps instead of
	// contending blindly. A nil runner keeps the original gate-only loop.
	// onSkipBudget observes a workspace deferred by the concurrency budget.
	runner       *tenancy.PeriodicRunner
	onSkipBudget func()
}

// NewSweeper wires the background sweep. engine and lister are required.
func NewSweeper(engine *Engine, lister WorkspaceLister, cfg Config) (*Sweeper, error) {
	if engine == nil {
		return nil, fmt.Errorf("discovery: Sweeper needs an engine")
	}
	if lister == nil {
		return nil, fmt.Errorf("discovery: Sweeper needs a workspace lister")
	}
	return &Sweeper{engine: engine, lister: lister, cfg: cfg.withDefaults()}, nil
}

// WithHibernationGate attaches the dormancy gate (and an optional skip observer)
// so a confidently-dormant workspace's sweep is deferred. A nil gate leaves the
// sweeper ungated (every workspace is swept). Returns the sweeper for chaining.
func (s *Sweeper) WithHibernationGate(gate HibernationGate, onSkipDormant func()) *Sweeper {
	s.gate = gate
	s.onSkipDormant = onSkipDormant
	return s
}

// WithPeriodicRunner routes each round's per-workspace sweeps through the shared
// tenancy fair-scheduler so the discovery sweep shares one global concurrency
// ceiling with the other periodic sweeps (credential rotation, ...) rather than
// each contending independently for the DB pool / upstreams. The runner owns
// the hibernation gate, so a runner-wired sweeper need not also set
// WithHibernationGate. onSkipDormant / onSkipBudget observe the two defer
// reasons for metrics. A nil runner keeps the original gate-only loop (used by
// the degraded build). Returns the sweeper for chaining.
func (s *Sweeper) WithPeriodicRunner(runner *tenancy.PeriodicRunner, onSkipDormant, onSkipBudget func()) *Sweeper {
	s.runner = runner
	s.onSkipDormant = onSkipDormant
	s.onSkipBudget = onSkipBudget
	return s
}

// Run blocks, sweeping every workspace once per SweepInterval until ctx is
// cancelled. It runs one round immediately on start so a freshly deployed engine
// evaluates existing policies without waiting a full interval.
func (s *Sweeper) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.cfg.SweepInterval)
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

// runOnce sweeps each workspace, logging and continuing past any single
// workspace's failure so one bad tenant cannot starve the fleet. With a
// fair-scheduler wired it fans the workspaces out under the shared global
// ceiling; otherwise it runs the original sequential gate-only loop.
func (s *Sweeper) runOnce(ctx context.Context) {
	ids, err := s.lister.WorkspaceIDs(ctx)
	if err != nil {
		logger.Errorf(ctx, "discovery: sweep: list workspaces: %v", err)
		return
	}
	if s.runner != nil {
		s.runScheduled(ctx, ids)
		return
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return
		}
		// Hibernation gate (scale-to-zero): defer a confidently-dormant
		// workspace's sweep. Fail-open — only a dormant classification skips;
		// an unclassified tenant or gate error still runs.
		if !s.shouldRun(ctx, id) {
			if s.onSkipDormant != nil {
				s.onSkipDormant()
			}
			continue
		}
		if _, err := s.engine.RunScheduledSweep(ctx, id); err != nil {
			logger.Errorf(ctx, "discovery: sweep: workspace %s: %v", id, err)
			continue
		}
	}
}

// runScheduled sweeps every workspace through the fair-scheduler: the gate and
// concurrency budgets live in the runner, the per-workspace sweep is the job,
// and a workspace deferred by the budget is simply re-swept next round (the
// sweep is idempotent). One workspace's failure is logged in its job closure
// and never starves the rest.
func (s *Sweeper) runScheduled(ctx context.Context, ids []uuid.UUID) {
	jobs := make([]tenancy.Job, 0, len(ids))
	for _, id := range ids {
		jobs = append(jobs, tenancy.Job{
			WorkspaceID: id,
			Run: func(ctx context.Context) error {
				if _, err := s.engine.RunScheduledSweep(ctx, id); err != nil {
					logger.Errorf(ctx, "discovery: sweep: workspace %s: %v", id, err)
					return err
				}
				return nil
			},
		})
	}
	s.runner.Sweep(ctx, jobs, func(out tenancy.Outcome, _ error) {
		if out == tenancy.OutcomeSkippedDormant && s.onSkipDormant != nil {
			s.onSkipDormant()
		} else if out == tenancy.OutcomeSkippedBudget && s.onSkipBudget != nil {
			s.onSkipBudget()
		}
	})
}

// shouldRun consults the hibernation gate fail-open: a nil gate or any gate
// error runs the workspace; only a confident dormant classification skips it.
func (s *Sweeper) shouldRun(ctx context.Context, workspaceID uuid.UUID) bool {
	if s.gate == nil {
		return true
	}
	run, err := s.gate.ShouldRunPeriodic(ctx, workspaceID)
	if err != nil {
		return true
	}
	return run
}
