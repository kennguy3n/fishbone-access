// Package workers implements the background job runner behind the
// access-connector-worker binary. It is a generic, dependency-injected poll
// loop: a Queue yields due jobs and a Processor handles them, with bounded
// retries and exponential backoff. The Postgres-backed Queue (claiming
// access_jobs rows with SELECT ... FOR UPDATE SKIP LOCKED) is the concrete
// implementation; this package defines the contract and the drain/backoff loop so
// that work plugs straight in.
package workers

import (
	"context"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Job is the unit of work pulled from the Queue. Payload is opaque to the
// runner; the Processor interprets it by Type.
type Job struct {
	ID       string
	Type     string
	Attempts int
	Payload  []byte
}

// Queue is the source of due jobs and the sink for terminal outcomes.
type Queue interface {
	// Claim atomically leases up to max due jobs, marking them in-flight so a
	// concurrent worker does not pick them up.
	Claim(ctx context.Context, max int) ([]Job, error)
	// Complete marks a job as successfully processed.
	Complete(ctx context.Context, jobID string) error
	// Fail records a processing error and reschedules the job for another
	// attempt at retryAt (the worker only calls this while attempts remain).
	Fail(ctx context.Context, jobID string, attempts int, cause error, retryAt time.Time) error
	// DeadLetter records a terminally-failed job. The worker calls this
	// instead of Fail once attempts reach the configured MaxAttempts, so the
	// job is not rescheduled.
	DeadLetter(ctx context.Context, jobID string, attempts int, cause error) error
}

// Processor handles a single job. Returning an error triggers Queue.Fail.
type Processor interface {
	Process(ctx context.Context, job Job) error
}

// ProcessorFunc adapts a function to Processor.
type ProcessorFunc func(ctx context.Context, job Job) error

// Process implements Processor.
func (f ProcessorFunc) Process(ctx context.Context, job Job) error { return f(ctx, job) }

// Config tunes the worker loop.
type Config struct {
	// PollInterval is how long to wait after an empty Claim before polling
	// again.
	PollInterval time.Duration
	// BatchSize is the maximum number of jobs leased per Claim.
	BatchSize int
	// MaxAttempts is the attempt count after which a failing job is
	// dead-lettered instead of retried.
	MaxAttempts int
	// BaseBackoff is the first retry delay; it doubles per attempt.
	BaseBackoff time.Duration
}

func (c Config) withDefaults() Config {
	if c.PollInterval <= 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 10
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = 5 * time.Second
	}
	return c
}

// Worker drains a Queue through a Processor until its context is cancelled.
type Worker struct {
	queue Queue
	proc  Processor
	cfg   Config
}

// New builds a Worker.
func New(queue Queue, proc Processor, cfg Config) *Worker {
	return &Worker{queue: queue, proc: proc, cfg: cfg.withDefaults()}
}

// Run blocks, draining jobs until ctx is cancelled. It returns ctx.Err() on
// shutdown so the caller can distinguish a clean stop.
func (w *Worker) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := w.drainOnce(ctx)
		if err != nil {
			logger.Errorf(ctx, "worker: claim failed: %v", err)
		}
		if n == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(w.cfg.PollInterval):
			}
		}
	}
}

// drainOnce claims and processes one batch, returning the number of jobs seen.
func (w *Worker) drainOnce(ctx context.Context) (int, error) {
	jobs, err := w.queue.Claim(ctx, w.cfg.BatchSize)
	if err != nil {
		return 0, err
	}
	for _, job := range jobs {
		w.handle(ctx, job)
	}
	return len(jobs), nil
}

func (w *Worker) handle(ctx context.Context, job Job) {
	if err := w.proc.Process(ctx, job); err != nil {
		attempts := job.Attempts + 1
		if attempts >= w.cfg.MaxAttempts {
			// Attempts exhausted: dead-letter instead of rescheduling.
			if derr := w.queue.DeadLetter(ctx, job.ID, attempts, err); derr != nil {
				logger.Errorf(ctx, "worker: dead-letter(%s) failed: %v", job.ID, derr)
			}
			return
		}
		retryAt := time.Now().Add(w.backoff(attempts))
		if ferr := w.queue.Fail(ctx, job.ID, attempts, err, retryAt); ferr != nil {
			logger.Errorf(ctx, "worker: fail(%s) failed: %v", job.ID, ferr)
		}
		return
	}
	if cerr := w.queue.Complete(ctx, job.ID); cerr != nil {
		logger.Errorf(ctx, "worker: complete(%s) failed: %v", job.ID, cerr)
	}
}

// backoff returns the delay before the n-th retry: BaseBackoff * 2^(n-1),
// capped at 1h.
func (w *Worker) backoff(attempt int) time.Duration {
	d := w.cfg.BaseBackoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= time.Hour {
			return time.Hour
		}
	}
	return d
}
