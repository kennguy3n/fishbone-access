package tenancy

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestFairSchedulerPerTenantCap(t *testing.T) {
	f := NewFairScheduler(100)
	ws := uuid.New()

	r1, ok := f.TryAcquire(ws, 2)
	if !ok {
		t.Fatal("first acquire should succeed")
	}
	r2, ok := f.TryAcquire(ws, 2)
	if !ok {
		t.Fatal("second acquire should succeed (cap 2)")
	}
	if _, ok := f.TryAcquire(ws, 2); ok {
		t.Fatal("third acquire should fail (over per-tenant cap)")
	}

	// Releasing one frees a per-tenant slot.
	r1()
	r3, ok := f.TryAcquire(ws, 2)
	if !ok {
		t.Fatal("acquire after release should succeed")
	}

	// release is idempotent — double-calling must not corrupt the counter.
	r1()
	r2()
	r3()
	// All released: a fresh acquire with cap 1 should work.
	if _, ok := f.TryAcquire(ws, 1); !ok {
		t.Fatal("acquire after full release should succeed")
	}
}

func TestFairSchedulerGlobalCeiling(t *testing.T) {
	f := NewFairScheduler(1)
	a := uuid.New()
	b := uuid.New()

	rel, ok := f.TryAcquire(a, 0) // 0 ⇒ no per-tenant cap
	if !ok {
		t.Fatal("first global slot should be acquirable")
	}
	if _, ok := f.TryAcquire(b, 0); ok {
		t.Fatal("second acquire should fail (global ceiling = 1)")
	}
	rel()
	if _, ok := f.TryAcquire(b, 0); !ok {
		t.Fatal("after release the global slot should be acquirable")
	}
}

func TestFairSchedulerAcquireBlocksThenCtx(t *testing.T) {
	f := NewFairScheduler(1)
	a := uuid.New()
	rel, _ := f.TryAcquire(a, 0)

	// Per-tenant cap hit → fail fast, no blocking.
	if _, err := f.Acquire(context.Background(), a, 1); !errors.Is(err, ErrTenantAtCapacity) {
		t.Fatalf("Acquire over cap err = %v, want ErrTenantAtCapacity", err)
	}

	// Global full → blocks until ctx cancels.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Acquire(ctx, uuid.New(), 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire blocked err = %v, want context.Canceled", err)
	}
	rel()
}

func TestFairSchedulerDefaultCeiling(t *testing.T) {
	// Non-positive ceiling must fall back to a positive default, never 0 (which
	// would deadlock every job).
	f := NewFairScheduler(0)
	if _, ok := f.TryAcquire(uuid.New(), 0); !ok {
		t.Fatal("default-ceiling scheduler should grant at least one slot")
	}
}

func TestFairSchedulerConcurrentReleaseRace(t *testing.T) {
	f := NewFairScheduler(8)
	ws := uuid.New()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rel, ok := f.TryAcquire(ws, 4); ok {
				rel()
			}
		}()
	}
	wg.Wait()
	// After the dust settles the tenant should hold no slots.
	f.mu.Lock()
	n := f.inflight[ws]
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("inflight after concurrent acquire/release = %d, want 0", n)
	}
}

func TestPeriodicRunnerOutcomes(t *testing.T) {
	ctx := context.Background()
	ws := uuid.New()

	t.Run("skips dormant", func(t *testing.T) {
		runner := NewPeriodicRunner(gateFunc(func() (bool, error) { return false, nil }), nil, NewFairScheduler(4))
		called := false
		out, err := runner.RunForTenant(ctx, ws, func(context.Context) error { called = true; return nil })
		if err != nil || out != OutcomeSkippedDormant {
			t.Fatalf("out=%v err=%v, want skipped_dormant", out, err)
		}
		if called {
			t.Error("job must not run for a dormant tenant")
		}
	})

	t.Run("runs active and propagates job error", func(t *testing.T) {
		runner := NewPeriodicRunner(gateFunc(func() (bool, error) { return true, nil }), nil, NewFairScheduler(4))
		sentinel := errors.New("boom")
		out, err := runner.RunForTenant(ctx, ws, func(context.Context) error { return sentinel })
		if out != OutcomeRan || !errors.Is(err, sentinel) {
			t.Fatalf("out=%v err=%v, want ran + sentinel", out, err)
		}
	})

	t.Run("fail-open on gate error", func(t *testing.T) {
		runner := NewPeriodicRunner(gateFunc(func() (bool, error) { return false, errors.New("db down") }), nil, NewFairScheduler(4))
		called := false
		out, _ := runner.RunForTenant(ctx, ws, func(context.Context) error { called = true; return nil })
		if out != OutcomeRan || !called {
			t.Fatalf("gate error should fail open and run; out=%v called=%v", out, called)
		}
	})

	t.Run("skips when global ceiling exhausted", func(t *testing.T) {
		sched := NewFairScheduler(1)
		hold, _ := sched.TryAcquire(uuid.New(), 0) // occupy the only slot
		defer hold()
		runner := NewPeriodicRunner(gateFunc(func() (bool, error) { return true, nil }), nil, sched)
		called := false
		out, err := runner.RunForTenant(ctx, ws, func(context.Context) error { called = true; return nil })
		if err != nil || out != OutcomeSkippedBudget {
			t.Fatalf("out=%v err=%v, want skipped_budget", out, err)
		}
		if called {
			t.Error("job must not run when no slot is available")
		}
	})
}

// gateFunc adapts a func to the HibernationGate interface.
type gateFunc func() (bool, error)

func (g gateFunc) ShouldRunPeriodic(context.Context, uuid.UUID) (bool, error) { return g() }
