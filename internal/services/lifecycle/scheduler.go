package lifecycle

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Scheduler runs the periodic lifecycle maintenance jobs: the grant-expiry
// sweep and the daily orphan-account reconciliation. It is a self-contained
// ticker loop (independent of the Session 1B Postgres worker queue) so the
// control plane enforces expiry and surfaces orphans even before the durable
// queue lands. Every job iterates workspaces explicitly; nothing runs unscoped.
type Scheduler struct {
	db      *gorm.DB
	expiry  *ExpiryEnforcer
	orphans *OrphanReconciler

	expiryInterval time.Duration
	orphanInterval time.Duration
}

// SchedulerConfig tunes the periodic intervals. Zero values fall back to
// sensible defaults (expiry every 5m, orphan scan every 24h).
type SchedulerConfig struct {
	ExpiryInterval time.Duration
	OrphanInterval time.Duration
}

// NewScheduler wires the periodic runner. orphans may be nil to disable the
// orphan sweep (e.g. when no connector resolver is configured).
func NewScheduler(db *gorm.DB, expiry *ExpiryEnforcer, orphans *OrphanReconciler, cfg SchedulerConfig) *Scheduler {
	s := &Scheduler{
		db:             db,
		expiry:         expiry,
		orphans:        orphans,
		expiryInterval: cfg.ExpiryInterval,
		orphanInterval: cfg.OrphanInterval,
	}
	if s.expiryInterval <= 0 {
		s.expiryInterval = 5 * time.Minute
	}
	if s.orphanInterval <= 0 {
		s.orphanInterval = 24 * time.Hour
	}
	return s
}

// Run blocks running both loops until ctx is cancelled. It returns ctx.Err().
// Each loop fires once on start so a freshly booted process does not wait a full
// interval before its first sweep.
func (s *Scheduler) Run(ctx context.Context) error {
	expiryTick := time.NewTicker(s.expiryInterval)
	orphanTick := time.NewTicker(s.orphanInterval)
	defer expiryTick.Stop()
	defer orphanTick.Stop()

	// Fire the initial sweeps, but bail out between them if ctx is already
	// cancelled so a process that is shutting down right after boot does not
	// kick off a (potentially slow, network-bound) orphan scan it will only
	// abandon. The per-workspace sweeps themselves honor ctx internally.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.runExpirySweep(ctx)
	if s.orphans != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.runOrphanSweep(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-expiryTick.C:
			s.runExpirySweep(ctx)
		case <-orphanTick.C:
			if s.orphans != nil {
				s.runOrphanSweep(ctx)
			}
		}
	}
}

// RunExpirySweep enforces expiry across every workspace once and returns the
// total number of grants expired. Exported so it can be triggered directly
// (e.g. an admin "run now" endpoint or a test) without the ticker loop.
func (s *Scheduler) RunExpirySweep(ctx context.Context) (int, error) {
	ids, err := s.workspaceIDs(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, ws := range ids {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		res, err := s.expiry.EnforceExpired(ctx, ws)
		if err != nil {
			logger.Errorf(ctx, "lifecycle: expiry sweep for workspace %s: %v", ws, err)
			continue
		}
		total += res.Expired
	}
	return total, nil
}

// RunOrphanSweep scans every connector in every workspace once (dry-run:
// persist newly-found orphans for operator disposition without mutating the
// data plane) and returns the number of orphans recorded.
func (s *Scheduler) RunOrphanSweep(ctx context.Context) (int, error) {
	if s.orphans == nil {
		return 0, nil
	}
	type row struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	var connectors []row
	if err := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Select("workspace_id", "id").
		Find(&connectors).Error; err != nil {
		return 0, err
	}
	total := 0
	for _, c := range connectors {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		res, err := s.orphans.Scan(ctx, c.WorkspaceID, c.ID, false)
		if err != nil {
			logger.Errorf(ctx, "lifecycle: orphan scan for connector %s: %v", c.ID, err)
			continue
		}
		total += res.PersistedCount
	}
	return total, nil
}

func (s *Scheduler) runExpirySweep(ctx context.Context) {
	n, err := s.RunExpirySweep(ctx)
	if err != nil {
		logger.Errorf(ctx, "lifecycle: expiry sweep: %v", err)
		return
	}
	if n > 0 {
		logger.Infof(ctx, "lifecycle: expiry sweep expired %d grant(s)", n)
	}
}

func (s *Scheduler) runOrphanSweep(ctx context.Context) {
	n, err := s.RunOrphanSweep(ctx)
	if err != nil {
		logger.Errorf(ctx, "lifecycle: orphan sweep: %v", err)
		return
	}
	if n > 0 {
		logger.Infof(ctx, "lifecycle: orphan sweep recorded %d orphan(s)", n)
	}
}

// workspaceIDs returns every workspace id so a periodic job can iterate tenants
// explicitly (never an unscoped cross-tenant query).
func (s *Scheduler) workspaceIDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := s.db.WithContext(ctx).
		Model(&models.Workspace{}).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}
