package workers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// Job status values persisted in access_jobs.status. The queue transitions a
// row through queued/retry → running → done|dead_letter.
const (
	// StatusQueued is a freshly-enqueued job awaiting its first attempt.
	StatusQueued = "queued"
	// StatusRunning is a job currently leased by a worker.
	StatusRunning = "running"
	// StatusRetry is a job that failed but has attempts remaining; it becomes
	// due again at run_after.
	StatusRetry = "retry"
	// StatusDone is a successfully processed job.
	StatusDone = "done"
	// StatusDeadLetter is a terminally-failed job: attempts exhausted, never
	// rescheduled. The row is retained (with last_error) for inspection.
	StatusDeadLetter = "dead_letter"
)

// PostgresQueue is the production Queue backed by the access_jobs table. It
// claims due jobs with SELECT ... FOR UPDATE SKIP LOCKED so any number of
// access-connector-worker replicas can drain the same queue without two
// workers ever leasing the same row. The SKIP LOCKED clause is Postgres-only;
// against SQLite (used in tests) the queue falls back to a plain transactional
// claim, which is safe because SQLite serialises writers.
type PostgresQueue struct {
	db *gorm.DB
	// skipLocked records whether the underlying driver supports
	// SELECT ... FOR UPDATE SKIP LOCKED. It is resolved once from the
	// authoritative outer handle's dialector at construction (the driver is
	// fixed for the queue's lifetime), rather than re-probed inside each claim
	// transaction, so the locking strategy can never be misdetected.
	skipLocked bool
	// jobTypes, when non-empty, scopes Claim to only these job types. It lets
	// multiple workers drain the SAME access_jobs table without stealing each
	// other's work: the connector worker filters to its connector job types and
	// the workflow engine filters to its workflow types, so a job is only ever
	// claimed by a worker that knows how to process it (an unfiltered worker
	// would claim a foreign type and dead-letter it). Empty = claim every type
	// (the original, backward-compatible behaviour).
	jobTypes []string
}

// QueueOption configures a PostgresQueue at construction.
type QueueOption func(*PostgresQueue)

// WithJobTypes scopes the queue's Claim to the given job types. Passing no
// types (or only empty strings) leaves the queue unfiltered. This is additive:
// existing callers that do not pass the option keep claiming every type.
func WithJobTypes(types ...string) QueueOption {
	return func(q *PostgresQueue) {
		filtered := make([]string, 0, len(types))
		for _, t := range types {
			if t != "" {
				filtered = append(filtered, t)
			}
		}
		q.jobTypes = filtered
	}
}

// NewPostgresQueue builds a queue over the given GORM handle.
func NewPostgresQueue(db *gorm.DB, opts ...QueueOption) *PostgresQueue {
	q := &PostgresQueue{db: db}
	if db != nil && db.Dialector != nil {
		// db.Name() is the dialector's Name() promoted through *Config; it is
		// fixed for the handle's lifetime, so the SKIP LOCKED decision is made
		// once here rather than re-probed on each claim's tx.
		q.skipLocked = db.Name() == "postgres"
	}
	for _, opt := range opts {
		opt(q)
	}
	return q
}

// Enqueue inserts a new job. workspaceID is required (tenant scoping);
// connectorID is optional (uuid.Nil for jobs not tied to a single connector).
// The payload is opaque to the queue — the Processor interprets it by jobType.
func (q *PostgresQueue) Enqueue(ctx context.Context, workspaceID, connectorID uuid.UUID, jobType string, payload []byte) (string, error) {
	if q == nil || q.db == nil {
		return "", fmt.Errorf("workers: PostgresQueue not initialised")
	}
	if workspaceID == uuid.Nil {
		return "", fmt.Errorf("workers: Enqueue: workspaceID required")
	}
	if jobType == "" {
		return "", fmt.Errorf("workers: Enqueue: jobType required")
	}
	job := models.AccessJob{
		Base:        models.Base{ID: uuid.New()},
		WorkspaceID: workspaceID,
		ConnectorID: connectorID,
		Type:        jobType,
		Status:      StatusQueued,
		RunAfter:    time.Now().UTC(),
	}
	if len(payload) > 0 {
		job.Payload = datatypes.JSON(payload)
	}
	if err := q.db.WithContext(ctx).Create(&job).Error; err != nil {
		return "", fmt.Errorf("workers: enqueue job: %w", err)
	}
	return job.ID.String(), nil
}

// Claim leases up to max due jobs (status queued/retry with run_after in the
// past), atomically flipping them to running so a concurrent worker skips them.
func (q *PostgresQueue) Claim(ctx context.Context, max int) ([]Job, error) {
	if q == nil || q.db == nil {
		return nil, fmt.Errorf("workers: PostgresQueue not initialised")
	}
	if max <= 0 {
		max = 1
	}
	var claimed []models.AccessJob
	err := q.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		sel := tx.Model(&models.AccessJob{}).
			Where("status IN ? AND run_after <= ?", []string{StatusQueued, StatusRetry}, time.Now().UTC()).
			Order("run_after").
			Limit(max)
		if len(q.jobTypes) > 0 {
			sel = sel.Where("type IN ?", q.jobTypes)
		}
		// FOR UPDATE SKIP LOCKED is the multi-worker safety net on Postgres;
		// SQLite rejects the clause and doesn't need it (single writer). The
		// driver is fixed for the queue's lifetime, so this is resolved once at
		// construction (q.skipLocked) instead of probed on the tx handle.
		if q.skipLocked {
			sel = sel.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
		}
		if err := sel.Find(&claimed).Error; err != nil {
			return err
		}
		if len(claimed) == 0 {
			return nil
		}
		ids := make([]uuid.UUID, len(claimed))
		for i := range claimed {
			ids[i] = claimed[i].ID
		}
		return tx.Model(&models.AccessJob{}).
			Where("id IN ?", ids).
			Updates(map[string]any{"status": StatusRunning, "updated_at": time.Now().UTC()}).Error
	})
	if err != nil {
		return nil, fmt.Errorf("workers: claim jobs: %w", err)
	}
	jobs := make([]Job, len(claimed))
	for i, c := range claimed {
		jobs[i] = Job{
			ID:       c.ID.String(),
			Type:     c.Type,
			Attempts: c.Attempts,
			Payload:  []byte(c.Payload),
		}
	}
	return jobs, nil
}

// Complete marks a job done.
func (q *PostgresQueue) Complete(ctx context.Context, jobID string) error {
	return q.updateStatus(ctx, jobID, map[string]any{
		"status":     StatusDone,
		"last_error": "",
		"updated_at": time.Now().UTC(),
	})
}

// Fail records the error, bumps the attempt count, and reschedules the job for
// retryAt by flipping it back to the retry state.
func (q *PostgresQueue) Fail(ctx context.Context, jobID string, attempts int, cause error, retryAt time.Time) error {
	return q.updateStatus(ctx, jobID, map[string]any{
		"status":     StatusRetry,
		"attempts":   attempts,
		"last_error": errString(cause),
		"run_after":  retryAt.UTC(),
		"updated_at": time.Now().UTC(),
	})
}

// DeadLetter records a terminally-failed job. The row is left in place with the
// final error so an operator can inspect or requeue it.
func (q *PostgresQueue) DeadLetter(ctx context.Context, jobID string, attempts int, cause error) error {
	return q.updateStatus(ctx, jobID, map[string]any{
		"status":     StatusDeadLetter,
		"attempts":   attempts,
		"last_error": errString(cause),
		"updated_at": time.Now().UTC(),
	})
}

func (q *PostgresQueue) updateStatus(ctx context.Context, jobID string, fields map[string]any) error {
	if q == nil || q.db == nil {
		return fmt.Errorf("workers: PostgresQueue not initialised")
	}
	id, err := uuid.Parse(jobID)
	if err != nil {
		return fmt.Errorf("workers: invalid job id %q: %w", jobID, err)
	}
	res := q.db.WithContext(ctx).Model(&models.AccessJob{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("workers: update job %s: %w", jobID, res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("workers: update job %s: %w", jobID, gorm.ErrRecordNotFound)
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Ensure PostgresQueue satisfies the Queue contract at compile time.
var _ Queue = (*PostgresQueue)(nil)
