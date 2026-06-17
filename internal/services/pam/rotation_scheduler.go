package pam

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
)

// hibernationGate decides whether a tenant's PERIODIC work should run now. The
// scheduler consults it before rotating any of a workspace's due targets and is
// fail-open by contract (unclassified or any error → run). Declared locally so
// this package needs no tenancy import; tenancy.Service satisfies it.
type hibernationGate interface {
	ShouldRunPeriodic(ctx context.Context, workspaceID uuid.UUID) (bool, error)
}

// dynamicReaper drops dynamic credentials whose lease ended or TTL lapsed. The
// scheduler runs it each tick. Optional (nil disables the reaper).
type dynamicReaper interface {
	ReapDue(ctx context.Context) (int, error)
}

// RotationSchedulerConfig tunes the periodic rotation sweep.
type RotationSchedulerConfig struct {
	// Interval is how often the scheduler scans for due rotations. Defaults to
	// 60s, matching the lease expiry sweep cadence — short enough that rotate-
	// on-checkin fires promptly after a lease ends, cheap enough at 5k tenants
	// because the scan is set-based (O(due rows), via partial indexes).
	Interval time.Duration
	// Actor recorded on scheduler-initiated rotations.
	Actor string
}

func (c RotationSchedulerConfig) withDefaults() RotationSchedulerConfig {
	if c.Interval <= 0 {
		c.Interval = 60 * time.Second
	}
	if c.Actor == "" {
		c.Actor = "rotation-scheduler"
	}
	return c
}

// RotationScheduler runs the periodic credential-rotation sweep inside the
// workflow engine. Each tick it selects the policies that are actually due
// (interval elapsed, or a lease checked in since the last rotation) with
// set-based queries, applies the hibernation gate per workspace so dormant
// tenants cost nothing, and rotates each due target through the shared engine.
// It also reaps expired dynamic credentials.
//
// The sweep is fail-open and idempotent: one target's failure never starves the
// rest, and a re-run after a crash simply re-selects whatever is still due.
type RotationScheduler struct {
	db     *gorm.DB
	engine *RotationEngine
	cfg    RotationSchedulerConfig
	now    func() time.Time

	gate          hibernationGate
	onSkipDormant func()
	reaper        dynamicReaper

	// runner, when set, replaces the inline sequential rotate loop with a
	// bounded-parallel fair-scheduled fan-out (see WithPeriodicRunner). It owns
	// the hibernation gate and per-tenant/global concurrency budgets, so the
	// local gate above is used only on the nil-runner (degraded / unit-test)
	// path. onSkipBudget observes a target deferred by the concurrency budget.
	runner       *tenancy.PeriodicRunner
	onSkipBudget func()
}

// NewRotationScheduler wires the scheduler. db and engine are required.
func NewRotationScheduler(db *gorm.DB, engine *RotationEngine, cfg RotationSchedulerConfig) (*RotationScheduler, error) {
	if db == nil {
		return nil, fmt.Errorf("pam: RotationScheduler needs a db handle")
	}
	if engine == nil {
		return nil, fmt.Errorf("pam: RotationScheduler needs an engine")
	}
	return &RotationScheduler{db: db, engine: engine, cfg: cfg.withDefaults(), now: time.Now}, nil
}

// SetClock overrides the time source (tests).
func (s *RotationScheduler) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// WithHibernationGate attaches the dormancy gate (and an optional skip observer).
// A nil gate leaves the scheduler ungated (every due workspace is swept).
func (s *RotationScheduler) WithHibernationGate(gate hibernationGate, onSkipDormant func()) *RotationScheduler {
	s.gate = gate
	s.onSkipDormant = onSkipDormant
	return s
}

// WithReaper attaches the dynamic-credential reaper run each tick.
func (s *RotationScheduler) WithReaper(r dynamicReaper) *RotationScheduler {
	s.reaper = r
	return s
}

// WithPeriodicRunner routes the sweep through the shared tenancy fair-scheduler
// so a tick's due rotations run with BOUNDED PARALLELISM instead of one at a
// time: many targets per tenant rotate concurrently up to the tenant's
// MaxConcurrentSyncs budget, and total in-flight across the fleet stays under
// the global ceiling — turning a long serial sweep into a short fair one while
// protecting the shared DB pool / upstreams. The runner also applies the
// hibernation gate, so a runner-wired scheduler need not also set
// WithHibernationGate. onSkipDormant / onSkipBudget observe the two defer
// reasons for metrics. A nil runner preserves the exact inline sequential
// behaviour (used by the degraded build and the unit tests).
func (s *RotationScheduler) WithPeriodicRunner(runner *tenancy.PeriodicRunner, onSkipDormant, onSkipBudget func()) *RotationScheduler {
	s.runner = runner
	s.onSkipDormant = onSkipDormant
	s.onSkipBudget = onSkipBudget
	return s
}

// Run blocks, sweeping once per Interval until ctx is cancelled. It runs one
// sweep immediately on start so a freshly deployed engine does not wait a full
// interval before the first rotation.
func (s *RotationScheduler) Run(ctx context.Context) error {
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

// runOnce performs one full sweep: interval-due rotations, checkin-due
// rotations, then the dynamic-credential reaper. Each phase logs and continues
// past a failure so one phase cannot starve another.
func (s *RotationScheduler) runOnce(ctx context.Context) {
	if n, err := s.sweepInterval(ctx); err != nil {
		logger.Errorf(ctx, "pam: rotation scheduler: interval sweep: %v", err)
	} else if n > 0 {
		logger.Infof(ctx, "pam: rotation scheduler: rotated %d target(s) on interval", n)
	}
	if n, err := s.sweepCheckin(ctx); err != nil {
		logger.Errorf(ctx, "pam: rotation scheduler: checkin sweep: %v", err)
	} else if n > 0 {
		logger.Infof(ctx, "pam: rotation scheduler: rotated %d target(s) on checkin", n)
	}
	if s.reaper != nil {
		if n, err := s.reaper.ReapDue(ctx); err != nil {
			logger.Errorf(ctx, "pam: rotation scheduler: reap dynamic credentials: %v", err)
		} else if n > 0 {
			logger.Infof(ctx, "pam: rotation scheduler: reaped %d dynamic credential(s)", n)
		}
	}
}

// dueRotation is one row of the set-based due-selection query.
type dueRotation struct {
	WorkspaceID uuid.UUID
	TargetID    uuid.UUID
	PolicyID    uuid.UUID
	LeaseID     *uuid.UUID
}

// sweepInterval rotates every target whose interval policy is due. The
// selection is a single indexed range scan over next_rotation_at — O(due rows).
func (s *RotationScheduler) sweepInterval(ctx context.Context) (int, error) {
	now := s.now().UTC()
	var due []dueRotation
	if err := s.db.WithContext(ctx).
		Model(&models.RotationPolicy{}).
		Select("workspace_id, target_id, id AS policy_id").
		Where("enabled = ? AND mode = ? AND next_rotation_at IS NOT NULL AND next_rotation_at <= ? AND deleted_at IS NULL",
			true, models.RotationModeInterval, now).
		Scan(&due).Error; err != nil {
		return 0, fmt.Errorf("pam: select interval-due policies: %w", err)
	}
	return s.rotateDue(ctx, due, models.RotationTriggerScheduled), nil
}

// sweepCheckin rotates every target with rotate-on-checkin whose lease has
// ended since the target last rotated. last_rotation_at advances on every
// attempt, so a given checkin triggers at most one rotation (idempotent).
func (s *RotationScheduler) sweepCheckin(ctx context.Context) (int, error) {
	var due []dueRotation
	// The correlated subqueries run only for the (small) set of rotate-on-checkin
	// policies, and the lease lookups are served by idx_pam_leases_target.
	if err := s.db.WithContext(ctx).
		Model(&models.RotationPolicy{}).
		// COALESCE(revoked_at, expired_at) is the lease's "ended at" instant
		// (revoke wins when both are set, since a revoke that follows an expiry
		// is the later event). Used instead of GREATEST so the same query runs
		// on Postgres (production) and SQLite (tests).
		Select(`pam_rotation_policies.workspace_id,
			pam_rotation_policies.target_id,
			pam_rotation_policies.id AS policy_id,
			(SELECT l.id FROM pam_leases l
			   WHERE l.target_id = pam_rotation_policies.target_id
			     AND l.workspace_id = pam_rotation_policies.workspace_id
			     AND (l.expired_at IS NOT NULL OR l.revoked_at IS NOT NULL)
			   ORDER BY COALESCE(l.revoked_at, l.expired_at) DESC
			   LIMIT 1) AS lease_id`).
		Where(`pam_rotation_policies.enabled = ? AND pam_rotation_policies.rotate_on_checkin = ? AND pam_rotation_policies.deleted_at IS NULL
			AND EXISTS (
				SELECT 1 FROM pam_leases l
				WHERE l.target_id = pam_rotation_policies.target_id
				  AND l.workspace_id = pam_rotation_policies.workspace_id
				  AND (l.expired_at IS NOT NULL OR l.revoked_at IS NOT NULL)
				  AND COALESCE(l.revoked_at, l.expired_at) > COALESCE(pam_rotation_policies.last_rotation_at, pam_rotation_policies.created_at)
			)`, true, true).
		Scan(&due).Error; err != nil {
		return 0, fmt.Errorf("pam: select checkin-due policies: %w", err)
	}
	return s.rotateDue(ctx, due, models.RotationTriggerCheckin), nil
}

// rotateDue rotates each due target and returns the count rotated. With a
// fair-scheduler wired (production) it fans the work out with bounded
// parallelism; otherwise it falls back to the inline sequential sweep.
func (s *RotationScheduler) rotateDue(ctx context.Context, due []dueRotation, trigger string) int {
	if s.runner == nil {
		return s.rotateDueInline(ctx, due, trigger)
	}
	return s.rotateDueScheduled(ctx, due, trigger)
}

// rotateOne rotates a single due target, logging and swallowing the error so a
// single target's failure never starves the rest of the sweep. Returns whether
// the rotation succeeded.
func (s *RotationScheduler) rotateOne(ctx context.Context, d dueRotation, trigger string) bool {
	leaseID := d.LeaseID
	if trigger != models.RotationTriggerCheckin {
		leaseID = nil
	}
	if _, err := s.engine.RotateTarget(ctx, d.WorkspaceID, d.TargetID, trigger, s.cfg.Actor, leaseID); err != nil {
		logger.Warnf(ctx, "pam: rotation scheduler: rotate target %s (%s): %v", d.TargetID, trigger, err)
		return false
	}
	return true
}

// rotateDueInline rotates each due target one at a time, applying the local
// hibernation gate once per workspace and continuing past any single failure.
func (s *RotationScheduler) rotateDueInline(ctx context.Context, due []dueRotation, trigger string) int {
	gateCache := map[uuid.UUID]bool{}
	rotated := 0
	for _, d := range due {
		run, cached := gateCache[d.WorkspaceID]
		if !cached {
			run = s.shouldRotate(ctx, d.WorkspaceID)
			gateCache[d.WorkspaceID] = run
		}
		if !run {
			if s.onSkipDormant != nil {
				s.onSkipDormant()
			}
			continue
		}
		if s.rotateOne(ctx, d, trigger) {
			rotated++
		}
	}
	return rotated
}

// rotateDueScheduled fans the due rotations out through the fair-scheduler:
// targets rotate concurrently up to each tenant's per-tenant budget and the
// fleet-wide global ceiling. A target deferred by the budget stays due
// (next_rotation_at only advances on an attempt) and is re-selected next tick,
// so deferral never drops a rotation. The hibernation gate and budgets live in
// the runner; this method only builds the jobs and tallies the outcomes.
func (s *RotationScheduler) rotateDueScheduled(ctx context.Context, due []dueRotation, trigger string) int {
	var rotated atomic.Int64
	jobs := make([]tenancy.Job, 0, len(due))
	for _, d := range due {
		jobs = append(jobs, tenancy.Job{
			WorkspaceID: d.WorkspaceID,
			Run: func(ctx context.Context) error {
				if s.rotateOne(ctx, d, trigger) {
					rotated.Add(1)
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
	return int(rotated.Load())
}

// shouldRotate applies the hibernation gate FAIL-OPEN: defer only when a gate
// is wired and confidently reports the workspace dormant. A nil gate, an
// unclassified tenant, or any gate error all rotate.
func (s *RotationScheduler) shouldRotate(ctx context.Context, workspaceID uuid.UUID) bool {
	if s.gate == nil {
		return true
	}
	run, err := s.gate.ShouldRunPeriodic(ctx, workspaceID)
	if err != nil {
		return true
	}
	return run
}
