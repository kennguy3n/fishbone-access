package tenancy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

// alwaysRun is a gate that never defers (every workspace is awake).
func alwaysRunGate() gateFunc { return gateFunc(func() (bool, error) { return true, nil }) }

// fixedBudget is a budgetResolver returning the same per-tenant cap for every
// workspace, so a Sweep test can pin MaxConcurrentSyncs deterministically.
type fixedBudget struct{ cap int }

func (b fixedBudget) BudgetFor(context.Context, uuid.UUID) (Budget, error) {
	return Budget{MaxConcurrentSyncs: b.cap}, nil
}

// TestSweepBoundedConcurrency proves the global ceiling actually binds: with a
// ceiling of N and more than N jobs (each across a distinct workspace so the
// per-tenant cap never binds), at most N run at once. It is fully deterministic
// — jobs park on a channel rather than sleeping — so exactly N reach the parked
// state, the launch loop blocks on the (N+1)th slot, and the observed peak is N.
func TestSweepBoundedConcurrency(t *testing.T) {
	const ceiling = 3
	const total = 7
	sched := NewFairScheduler(ceiling)
	// nil budgets ⇒ no per-tenant cap, so only the global ceiling binds.
	runner := NewPeriodicRunner(alwaysRunGate(), nil, sched)

	started := make(chan struct{}, total)
	release := make(chan struct{})
	var cur, peak, ran int64
	var peakMu sync.Mutex

	jobs := make([]Job, total)
	for i := range jobs {
		jobs[i] = Job{
			WorkspaceID: uuid.New(),
			Run: func(context.Context) error {
				n := atomic.AddInt64(&cur, 1)
				peakMu.Lock()
				if n > peak {
					peak = n
				}
				peakMu.Unlock()
				started <- struct{}{}
				<-release
				atomic.AddInt64(&cur, -1)
				atomic.AddInt64(&ran, 1)
				return nil
			},
		}
	}

	done := make(chan struct{})
	go func() {
		runner.Sweep(context.Background(), jobs, nil)
		close(done)
	}()

	// Exactly ceiling jobs can park; the launch loop is now blocked acquiring
	// the (ceiling+1)th global slot, which only frees once we release.
	for i := 0; i < ceiling; i++ {
		<-started
	}
	if got := atomic.LoadInt64(&cur); got != ceiling {
		t.Fatalf("in-flight at saturation = %d, want %d", got, ceiling)
	}

	close(release)
	<-done

	if ran != total {
		t.Fatalf("ran = %d, want %d (every job must eventually run)", ran, total)
	}
	peakMu.Lock()
	defer peakMu.Unlock()
	if peak != ceiling {
		t.Fatalf("peak concurrency = %d, want %d (global ceiling must bind)", peak, ceiling)
	}
}

// TestSweepSkipsDormant verifies a dormant workspace's jobs are reported skipped
// and never run.
func TestSweepSkipsDormant(t *testing.T) {
	runner := NewPeriodicRunner(gateFunc(func() (bool, error) { return false, nil }), nil, NewFairScheduler(4))
	var ran, dormant int64
	jobs := []Job{
		{WorkspaceID: uuid.New(), Run: func(context.Context) error { atomic.AddInt64(&ran, 1); return nil }},
		{WorkspaceID: uuid.New(), Run: func(context.Context) error { atomic.AddInt64(&ran, 1); return nil }},
	}
	runner.Sweep(context.Background(), jobs, func(out Outcome, _ error) {
		if out == OutcomeSkippedDormant {
			atomic.AddInt64(&dormant, 1)
		}
	})
	if ran != 0 {
		t.Fatalf("ran = %d, want 0 (dormant tenant)", ran)
	}
	if dormant != int64(len(jobs)) {
		t.Fatalf("dormant observations = %d, want %d", dormant, len(jobs))
	}
}

// TestSweepDefersOverBudget pins the per-tenant cap to 1 and pre-holds that one
// slot, so the tenant's single Sweep job is deferred (OutcomeSkippedBudget),
// deterministically and without running it.
func TestSweepDefersOverBudget(t *testing.T) {
	sched := NewFairScheduler(8)
	ws := uuid.New()
	// Pre-hold the tenant's only slot (cap 1) so the Sweep job hits the cap.
	hold, ok := sched.TryAcquire(ws, 1)
	if !ok {
		t.Fatal("pre-hold acquire should succeed")
	}
	defer hold()

	runner := NewPeriodicRunner(alwaysRunGate(), fixedBudget{cap: 1}, sched)
	var ran, budget int64
	jobs := []Job{{WorkspaceID: ws, Run: func(context.Context) error { atomic.AddInt64(&ran, 1); return nil }}}
	runner.Sweep(context.Background(), jobs, func(out Outcome, _ error) {
		if out == OutcomeSkippedBudget {
			atomic.AddInt64(&budget, 1)
		}
	})
	if ran != 0 {
		t.Fatalf("ran = %d, want 0 (over per-tenant budget)", ran)
	}
	if budget != 1 {
		t.Fatalf("budget-skip observations = %d, want 1", budget)
	}
}

// TestSweepNilSchedulerRunsInline verifies the degraded path: with no scheduler
// every awake job still runs (unbounded, inline).
func TestSweepNilSchedulerRunsInline(t *testing.T) {
	runner := NewPeriodicRunner(alwaysRunGate(), nil, nil)
	var ran int64
	jobs := make([]Job, 5)
	for i := range jobs {
		jobs[i] = Job{WorkspaceID: uuid.New(), Run: func(context.Context) error { atomic.AddInt64(&ran, 1); return nil }}
	}
	runner.Sweep(context.Background(), jobs, nil)
	if ran != int64(len(jobs)) {
		t.Fatalf("ran = %d, want %d (nil scheduler must still run every job)", ran, len(jobs))
	}
}

// TestSweepStopsLaunchingOnCancel verifies a cancelled context stops launching
// further jobs (no job runs when ctx is already cancelled).
func TestSweepStopsLaunchingOnCancel(t *testing.T) {
	runner := NewPeriodicRunner(alwaysRunGate(), nil, NewFairScheduler(4))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ran int64
	jobs := make([]Job, 3)
	for i := range jobs {
		jobs[i] = Job{WorkspaceID: uuid.New(), Run: func(context.Context) error { atomic.AddInt64(&ran, 1); return nil }}
	}
	runner.Sweep(ctx, jobs, nil)
	if ran != 0 {
		t.Fatalf("ran = %d, want 0 (cancelled before launch)", ran)
	}
}
