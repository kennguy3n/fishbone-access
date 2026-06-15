package recordings

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// WorkspaceLister enumerates the workspaces a sweep covers. The workflow
// engine's GormWorkspaceLister satisfies it; declared here so this package needs
// no dependency on that package (the wiring points one way, main → recordings).
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

// SweepConfig tunes the background index + retention sweep.
type SweepConfig struct {
	// Interval is how often the sweep runs a full round over all workspaces.
	// Defaults to 1h — recordings are not latency-sensitive to index, and a
	// modest cadence keeps the fleet-wide cost negligible.
	Interval time.Duration
	// DefaultRetentionDays is the plan/global retention default applied to a
	// workspace with no explicit override. 0 means "retain indefinitely" by
	// default, so pruning only happens for workspaces that opt in — a safe
	// default that never deletes evidence without configuration.
	DefaultRetentionDays int
	// IndexBatch caps how many unindexed sessions a workspace indexes per round
	// (bounded work per tenant). PruneBatch caps blobs tiered per round.
	IndexBatch int
	PruneBatch int
}

func (c SweepConfig) withDefaults() SweepConfig {
	if c.Interval <= 0 {
		c.Interval = time.Hour
	}
	if c.IndexBatch <= 0 {
		c.IndexBatch = 200
	}
	if c.PruneBatch <= 0 {
		c.PruneBatch = 200
	}
	if c.DefaultRetentionDays < 0 {
		c.DefaultRetentionDays = 0
	}
	return c
}

// Sweeper runs the periodic, fail-open background maintenance for the recordings
// store: it indexes finished sessions into the searchable projection and tiers
// expired blobs out of object storage per the retention policy. It respects
// tenant hibernation (a confidently-dormant workspace is skipped, scale-to-zero)
// and never lets one workspace's failure starve the rest.
type Sweeper struct {
	svc    *Service
	lister WorkspaceLister
	cfg    SweepConfig

	gate          HibernationGate
	onSkipDormant func()
}

// NewSweeper wires the background sweep. svc and lister are required.
func NewSweeper(svc *Service, lister WorkspaceLister, cfg SweepConfig) (*Sweeper, error) {
	if svc == nil {
		return nil, fmt.Errorf("recordings: Sweeper needs a service")
	}
	if lister == nil {
		return nil, fmt.Errorf("recordings: Sweeper needs a workspace lister")
	}
	return &Sweeper{svc: svc, lister: lister, cfg: cfg.withDefaults()}, nil
}

// WithHibernationGate attaches the dormancy gate (and an optional skip observer)
// so a confidently-dormant workspace's index/prune round is deferred. A nil gate
// leaves the sweeper ungated (every workspace is swept), matching the
// pre-hibernation behaviour. Returns the sweeper for chaining.
func (s *Sweeper) WithHibernationGate(gate HibernationGate, onSkipDormant func()) *Sweeper {
	s.gate = gate
	s.onSkipDormant = onSkipDormant
	return s
}

// Run blocks, sweeping every workspace once per Interval until ctx is
// cancelled. It runs one round immediately on start so a freshly deployed engine
// indexes the existing backlog without waiting a full interval.
func (s *Sweeper) Run(ctx context.Context) error {
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

// runOnce indexes + prunes each workspace, logging and continuing past any
// single workspace's failure so one bad tenant cannot starve the fleet.
func (s *Sweeper) runOnce(ctx context.Context) {
	ids, err := s.lister.WorkspaceIDs(ctx)
	if err != nil {
		logger.Errorf(ctx, "recordings: sweep: list workspaces: %v", err)
		return
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return
		}
		// Hibernation gate (scale-to-zero): defer a confidently-dormant
		// workspace's index/prune round. Fail-open — only a dormant
		// classification skips; an unclassified tenant or gate error still runs.
		if !s.shouldRun(ctx, id) {
			if s.onSkipDormant != nil {
				s.onSkipDormant()
			}
			continue
		}
		if _, err := s.svc.IndexClosedSessions(ctx, id, s.cfg.IndexBatch); err != nil {
			logger.Errorf(ctx, "recordings: sweep: index workspace %s: %v", id, err)
			// fall through to prune — indexing and pruning are independent
		}
		if _, err := s.svc.PruneExpiredBlobs(ctx, id, s.cfg.DefaultRetentionDays, s.cfg.PruneBatch); err != nil {
			logger.Errorf(ctx, "recordings: sweep: prune workspace %s: %v", id, err)
			continue
		}
	}
}

// shouldRun applies the hibernation gate FAIL-OPEN: false (defer) ONLY when a
// gate is wired and confidently reports the workspace dormant. A nil gate, an
// unclassified tenant, or any gate error all yield true (run).
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
