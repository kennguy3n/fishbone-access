package lifecycle

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// connectorStatusPending mirrors the AccessConnector.Status column default
// ("pending") declared in the models package. A connector in this state has
// never been configured, so the orphan sweep skips it (see RunOrphanSweep).
// Defined here in the lifecycle package rather than models to keep 1C scoped to
// lifecycle/policy and avoid colliding with the 1B connector framework's own
// status vocabulary.
const connectorStatusPending = "pending"

// Scheduler runs the periodic lifecycle maintenance jobs: the grant-expiry
// sweep and the daily orphan-account reconciliation. It is a self-contained
// ticker loop (independent of the Session 1B Postgres worker queue) so the
// control plane enforces expiry and surfaces orphans even before the durable
// queue lands. Every job iterates workspaces explicitly; nothing runs unscoped.
type Scheduler struct {
	db      *gorm.DB
	expiry  *ExpiryEnforcer
	orphans *OrphanReconciler
	// anomaly and contractor are optional (nil disables the corresponding
	// sweep); they are attached after construction via the Set* methods so the
	// NewScheduler signature stays stable for existing callers.
	anomaly    *AnomalyDetector
	contractor *ContractorExpiryEnforcer

	expiryInterval     time.Duration
	orphanInterval     time.Duration
	anomalyInterval    time.Duration
	contractorInterval time.Duration
}

// SchedulerConfig tunes the periodic intervals. Zero values fall back to
// sensible defaults (expiry every 5m, orphan scan every 24h, anomaly detection
// every 1h, contractor expiry every 5m).
type SchedulerConfig struct {
	ExpiryInterval     time.Duration
	OrphanInterval     time.Duration
	AnomalyInterval    time.Duration
	ContractorInterval time.Duration
}

// NewScheduler wires the periodic runner. orphans may be nil to disable the
// orphan sweep (e.g. when no connector resolver is configured).
func NewScheduler(db *gorm.DB, expiry *ExpiryEnforcer, orphans *OrphanReconciler, cfg SchedulerConfig) *Scheduler {
	s := &Scheduler{
		db:                 db,
		expiry:             expiry,
		orphans:            orphans,
		expiryInterval:     cfg.ExpiryInterval,
		orphanInterval:     cfg.OrphanInterval,
		anomalyInterval:    cfg.AnomalyInterval,
		contractorInterval: cfg.ContractorInterval,
	}
	if s.expiryInterval <= 0 {
		s.expiryInterval = 5 * time.Minute
	}
	if s.orphanInterval <= 0 {
		s.orphanInterval = 24 * time.Hour
	}
	if s.anomalyInterval <= 0 {
		s.anomalyInterval = time.Hour
	}
	if s.contractorInterval <= 0 {
		s.contractorInterval = 5 * time.Minute
	}
	return s
}

// SetAnomalyDetector attaches the SoD anomaly→evidence detector so its periodic
// sweep runs. nil leaves the sweep disabled.
func (s *Scheduler) SetAnomalyDetector(d *AnomalyDetector) { s.anomaly = d }

// SetContractorEnforcer attaches the contractor-grant expiry enforcer so its
// periodic sweep runs. nil leaves the sweep disabled.
func (s *Scheduler) SetContractorEnforcer(e *ContractorExpiryEnforcer) { s.contractor = e }

// Run blocks running both loops until ctx is cancelled. It returns ctx.Err().
// Each loop fires once on start so a freshly booted process does not wait a full
// interval before its first sweep.
func (s *Scheduler) Run(ctx context.Context) error {
	expiryTick := time.NewTicker(s.expiryInterval)
	defer expiryTick.Stop()

	// Optional sweeps get a ticker only when their dependency is wired. A nil
	// channel is never selected, so a disabled sweep costs no ticker goroutine
	// and its select case below is inert without an explicit nil guard.
	var orphanC, anomalyC, contractorC <-chan time.Time
	if s.orphans != nil {
		t := time.NewTicker(s.orphanInterval)
		defer t.Stop()
		orphanC = t.C
	}
	if s.anomaly != nil {
		t := time.NewTicker(s.anomalyInterval)
		defer t.Stop()
		anomalyC = t.C
	}
	if s.contractor != nil {
		t := time.NewTicker(s.contractorInterval)
		defer t.Stop()
		contractorC = t.C
	}

	// Fire the initial sweeps, but bail out between them if ctx is already
	// cancelled so a process that is shutting down right after boot does not
	// kick off a (potentially slow, network-bound) orphan scan it will only
	// abandon. The per-workspace sweeps themselves honor ctx internally.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.runExpirySweep(ctx)
	if s.contractor != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.runContractorSweep(ctx)
	}
	if s.orphans != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.runOrphanSweep(ctx)
	}
	if s.anomaly != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.runAnomalySweep(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-expiryTick.C:
			s.runExpirySweep(ctx)
		case <-orphanC:
			s.runOrphanSweep(ctx)
		case <-anomalyC:
			s.runAnomalySweep(ctx)
		case <-contractorC:
			s.runContractorSweep(ctx)
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
	// Skip connectors that have never been configured ("pending" is the model
	// default applied at insert). Such a connector has no synced identities, so
	// resolving it always fails and the periodic sweep would log that error on
	// every interval. Excluding it removes the recurring noise without risking
	// skipping a configured connector: anything past the initial pending state
	// (e.g. active, or a future disabled state owned by 1B) is still scanned, so
	// orphans on a deactivated connector are still surfaced. The leaver kill
	// switch deliberately keeps sweeping every connector regardless of status —
	// that path is security-critical and must over-revoke, whereas this is
	// best-effort maintenance.
	if err := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Select("workspace_id", "id").
		Where("status <> ?", connectorStatusPending).
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

// RunAnomalySweep detects standing SoD violations across every workspace once,
// recording + evidencing any new ones, and returns the total number of new
// anomalies recorded. Exported so it can be triggered directly (e.g. a seeded
// scenario or a test) without the ticker loop.
func (s *Scheduler) RunAnomalySweep(ctx context.Context) (int, error) {
	if s.anomaly == nil {
		return 0, nil
	}
	ids, err := s.workspaceIDs(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, ws := range ids {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := s.anomaly.DetectAndRecord(ctx, ws)
		if err != nil {
			logger.Errorf(ctx, "lifecycle: anomaly sweep for workspace %s: %v", ws, err)
			continue
		}
		total += n
	}
	return total, nil
}

// RunContractorExpirySweep expires + deprovisions every contractor grant past
// its time box across every workspace once, returning the total number revoked.
// Exported so it can be triggered directly (e.g. a test) without the ticker loop.
func (s *Scheduler) RunContractorExpirySweep(ctx context.Context) (int, error) {
	if s.contractor == nil {
		return 0, nil
	}
	ids, err := s.workspaceIDs(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, ws := range ids {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := s.contractor.EnforceExpired(ctx, ws)
		if err != nil {
			logger.Errorf(ctx, "lifecycle: contractor expiry sweep for workspace %s: %v", ws, err)
			continue
		}
		total += n
	}
	return total, nil
}

func (s *Scheduler) runAnomalySweep(ctx context.Context) {
	n, err := s.RunAnomalySweep(ctx)
	if err != nil {
		logger.Errorf(ctx, "lifecycle: anomaly sweep: %v", err)
		return
	}
	if n > 0 {
		logger.Infof(ctx, "lifecycle: anomaly sweep recorded %d anomaly evidence record(s)", n)
	}
}

func (s *Scheduler) runContractorSweep(ctx context.Context) {
	n, err := s.RunContractorExpirySweep(ctx)
	if err != nil {
		logger.Errorf(ctx, "lifecycle: contractor expiry sweep: %v", err)
		return
	}
	if n > 0 {
		logger.Infof(ctx, "lifecycle: contractor expiry sweep revoked %d grant(s)", n)
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
