package tenancy

import (
	"context"
	"errors"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// reconciler is the subset of Service the loop needs (testability).
type reconciler interface {
	Reconcile(ctx context.Context) (ReconcileResult, error)
}

// ReconcileLoop periodically runs the dormancy sweep. It is a self-contained
// ticker (like the lifecycle scheduler) so the control plane re-classifies
// tenants without an external cron. The sweep is set-based and idempotent, so
// running it on every replica is safe — each run converges the same state.
type ReconcileLoop struct {
	svc      reconciler
	interval time.Duration
}

// NewReconcileLoop wires the loop. A non-positive interval falls back to 15m.
func NewReconcileLoop(svc reconciler, interval time.Duration) *ReconcileLoop {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	return &ReconcileLoop{svc: svc, interval: interval}
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
}
