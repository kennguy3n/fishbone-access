package tenancy

import (
	"context"
	"errors"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// reconciler is the subset of Service the loop needs (testability). CountDormant
// lets the loop publish the fleet-wide dormant gauge after each sweep without
// the loop knowing anything about Prometheus.
type reconciler interface {
	Reconcile(ctx context.Context) (ReconcileResult, error)
	CountDormant(ctx context.Context) (int64, error)
}

// ReconcileLoop periodically runs the dormancy sweep. It is a self-contained
// ticker (like the lifecycle scheduler) so the control plane re-classifies
// tenants without an external cron. The sweep is set-based and idempotent, so
// running it on every replica is safe — each run converges the same state.
type ReconcileLoop struct {
	svc      reconciler
	interval time.Duration
	// onDormantCount, when non-nil, is called after every successful sweep with
	// the current fleet-wide dormant count, so production can publish the
	// scale-to-zero gauge. It is the nil-able observer seam (mirroring the usage
	// aggregator's Observe hook) that keeps this package free of an observability
	// dependency. A nil hook makes the loop a pure classifier.
	onDormantCount func(int64)
}

// NewReconcileLoop wires the loop. A non-positive interval falls back to 15m.
func NewReconcileLoop(svc reconciler, interval time.Duration) *ReconcileLoop {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	return &ReconcileLoop{svc: svc, interval: interval}
}

// WithDormantObserver attaches a hook called after each successful sweep with
// the current dormant count. Returns the loop for chaining at the call site.
func (l *ReconcileLoop) WithDormantObserver(fn func(int64)) *ReconcileLoop {
	l.onDormantCount = fn
	return l
}

// Run starts the loop in a goroutine and returns a join function that blocks
// until it has stopped, mirroring the recorder/scheduler lifecycle so shutdown
// is race-free against the DB pool close. It fires one sweep immediately so a
// freshly booted process classifies tenants without waiting a full interval.
func (l *ReconcileLoop) Run(ctx context.Context) (join func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.sweep(ctx)
		t := time.NewTicker(l.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l.sweep(ctx)
			}
		}
	}()
	return func() { <-done }
}

func (l *ReconcileLoop) sweep(ctx context.Context) {
	res, err := l.svc.Reconcile(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Errorf(ctx, "tenancy: dormancy reconcile sweep: %v", err)
		}
		return
	}
	if res.Seeded > 0 || res.Hibernated > 0 || res.Woken > 0 {
		logger.Infof(ctx, "tenancy: dormancy sweep: seeded=%d hibernated=%d woken=%d",
			res.Seeded, res.Hibernated, res.Woken)
	}
	// Refresh the scale-to-zero gauge from the authoritative state column rather
	// than tracking deltas, so the gauge is self-correcting and a missed sweep
	// can never leave it drifted. Skipped entirely when no observer is wired.
	if l.onDormantCount != nil {
		n, err := l.svc.CountDormant(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				logger.Warnf(ctx, "tenancy: count dormant for gauge: %v", err)
			}
			return
		}
		l.onDormantCount(n)
	}
}
