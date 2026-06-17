package tenancy

import (
	"context"
	"errors"
	"runtime"
	"sync"

	"github.com/google/uuid"
)

// ErrTenantAtCapacity is returned by FairScheduler.Acquire when the tenant
// already holds its full per-tenant concurrency budget. It is not a failure of
// the work — the caller should defer the job and retry on the next tick.
var ErrTenantAtCapacity = errors.New("tenancy: tenant at concurrency budget")

// FairScheduler bounds concurrent periodic work two ways at once, so background
// work is shared fairly across the fleet instead of first-come-first-served:
//
//   - A GLOBAL ceiling caps total simultaneous periodic jobs across all
//     tenants, protecting shared resources (DB pool, upstream rate limits, CPU)
//     regardless of how many tenants wake at once.
//   - A PER-TENANT cap (from the tenant's Budget.MaxConcurrentSyncs) stops any
//     single tenant from claiming an unfair slice of the global ceiling, so a
//     busy or misbehaving tenant cannot starve the others.
//
// Together with the HibernationGate (dormant tenants never reach the scheduler)
// this is what lets one active tenant's burst not degrade the rest, and the
// dormant majority cost nothing.
type FairScheduler struct {
	global chan struct{} // buffered to the global ceiling

	mu       sync.Mutex
	inflight map[uuid.UUID]int
}

// NewFairScheduler builds a scheduler with the given global concurrency
// ceiling. A non-positive ceiling falls back to 4×GOMAXPROCS (a sane default
// for IO-bound connector work), so a mis-set config cannot produce a zero-slot
// scheduler that deadlocks every job.
func NewFairScheduler(globalCeiling int) *FairScheduler {
	if globalCeiling <= 0 {
		globalCeiling = 4 * runtime.GOMAXPROCS(0)
	}
	return &FairScheduler{
		global:   make(chan struct{}, globalCeiling),
		inflight: make(map[uuid.UUID]int),
	}
}

// TryAcquire reserves a slot without blocking. It returns a release function and
// true on success, or (nil, false) when either the tenant is at its per-tenant
// cap or the global ceiling is full. release is idempotent.
func (f *FairScheduler) TryAcquire(workspaceID uuid.UUID, maxPerTenant int) (release func(), ok bool) {
	if !f.reserveTenant(workspaceID, maxPerTenant) {
		return nil, false
	}
	select {
	case f.global <- struct{}{}:
		return f.releaseFunc(workspaceID), true
	default:
		f.releaseTenant(workspaceID)
		return nil, false
	}
}

// Acquire reserves a slot, blocking for a global slot until one frees up or ctx
// is cancelled. It fails fast with ErrTenantAtCapacity if the tenant is already
// at its per-tenant cap (blocking there could deadlock a single tenant against
// itself). release is idempotent.
func (f *FairScheduler) Acquire(ctx context.Context, workspaceID uuid.UUID, maxPerTenant int) (release func(), err error) {
	if !f.reserveTenant(workspaceID, maxPerTenant) {
		return nil, ErrTenantAtCapacity
	}
	select {
	case f.global <- struct{}{}:
		return f.releaseFunc(workspaceID), nil
	case <-ctx.Done():
		f.releaseTenant(workspaceID)
		return nil, ctx.Err()
	}
}

func (f *FairScheduler) reserveTenant(workspaceID uuid.UUID, maxPerTenant int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if maxPerTenant > 0 && f.inflight[workspaceID] >= maxPerTenant {
		return false
	}
	f.inflight[workspaceID]++
	return true
}

func (f *FairScheduler) releaseTenant(workspaceID uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.inflight[workspaceID]; n > 1 {
		f.inflight[workspaceID] = n - 1
	} else {
		// Drop the key at zero so the map tracks only currently-active tenants
		// rather than every tenant ever scheduled.
		delete(f.inflight, workspaceID)
	}
}

func (f *FairScheduler) releaseFunc(workspaceID uuid.UUID) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-f.global
			f.releaseTenant(workspaceID)
		})
	}
}

// Outcome is the result of a PeriodicRunner attempt for one tenant.
type Outcome int

const (
	// OutcomeRan means the job was executed (err carries the job's own error).
	OutcomeRan Outcome = iota
	// OutcomeSkippedDormant means the tenant is hibernated; no work was done.
	OutcomeSkippedDormant
	// OutcomeSkippedBudget means the tenant or the fleet was at its concurrency
	// budget; the job should be retried on the next tick.
	OutcomeSkippedBudget
)

// String renders the outcome for logs/metrics.
func (o Outcome) String() string {
	switch o {
	case OutcomeRan:
		return "ran"
	case OutcomeSkippedDormant:
		return "skipped_dormant"
	case OutcomeSkippedBudget:
		return "skipped_budget"
	default:
		return "unknown"
	}
}

// budgetResolver is the subset of Service a PeriodicRunner needs. Narrowed for
// testability; *Service satisfies it.
type budgetResolver interface {
	BudgetFor(ctx context.Context, workspaceID uuid.UUID) (Budget, error)
}

// PeriodicRunner is the clean interface a periodic worker (connector sync,
// reconciler, scheduler) consults to do work for a tenant correctly under the
// NoOps model — WITHOUT the worker needing to know anything about dormancy or
// budgets. The worker just enumerates its workspaces and calls RunForTenant;
// the runner applies the hibernation gate and fair scheduling. This keeps the
// scale logic in one owned place and out of every worker.
type PeriodicRunner struct {
	gate    HibernationGate
	budgets budgetResolver
	sched   *FairScheduler
}

// NewPeriodicRunner wires a runner. Any of gate/budgets/sched may be nil for a
// degraded build: a nil gate runs every tenant, a nil budget resolver imposes
// no per-tenant cap, and a nil scheduler imposes no global ceiling.
func NewPeriodicRunner(gate HibernationGate, budgets budgetResolver, sched *FairScheduler) *PeriodicRunner {
	return &PeriodicRunner{gate: gate, budgets: budgets, sched: sched}
}

// shouldRun applies the hibernation gate FAIL-OPEN: a nil gate or any gate
// error runs the tenant; only a confident dormant classification skips it.
// Deferring real work because a classification read hiccuped would be worse
// than running it.
func (p *PeriodicRunner) shouldRun(ctx context.Context, workspaceID uuid.UUID) bool {
	if p.gate == nil {
		return true
	}
	run, err := p.gate.ShouldRunPeriodic(ctx, workspaceID)
	if err != nil {
		return true
	}
	return run
}

// maxPerTenant resolves the tenant's per-tenant concurrency cap FAIL-OPEN: a
// nil budget resolver or any read error imposes no per-tenant cap (0), so the
// global ceiling alone bounds total work rather than a transient read error
// wedging a tenant.
func (p *PeriodicRunner) maxPerTenant(ctx context.Context, workspaceID uuid.UUID) int {
	if p.budgets == nil {
		return 0
	}
	b, err := p.budgets.BudgetFor(ctx, workspaceID)
	if err != nil {
		return 0
	}
	return b.MaxConcurrentSyncs
}

// RunForTenant runs job for one tenant iff it is awake and a fair-scheduling
// slot is available within the tenant's budget. It is the SINGLE-TENANT,
// NON-BLOCKING form — a busy slot is skipped immediately (the caller retries on
// the next tick). For a whole sweep of many tenants, prefer Sweep, which fans
// the work out with bounded fair concurrency.
//
//   - dormant tenant            → (OutcomeSkippedDormant, nil), job not called
//   - at concurrency budget     → (OutcomeSkippedBudget, nil), job not called
//   - otherwise                 → (OutcomeRan, job(ctx)), slot released after
func (p *PeriodicRunner) RunForTenant(ctx context.Context, workspaceID uuid.UUID, job func(context.Context) error) (Outcome, error) {
	if !p.shouldRun(ctx, workspaceID) {
		return OutcomeSkippedDormant, nil
	}
	if p.sched != nil {
		release, ok := p.sched.TryAcquire(workspaceID, p.maxPerTenant(ctx, workspaceID))
		if !ok {
			return OutcomeSkippedBudget, nil
		}
		defer release()
	}
	return OutcomeRan, job(ctx)
}

// Job is one unit of periodic work tagged with the workspace that owns it. The
// same workspace may own MANY jobs in a single sweep (e.g. one per due rotation
// target); Sweep gates the workspace once and bounds that workspace's
// concurrent jobs by its per-tenant budget.
type Job struct {
	WorkspaceID uuid.UUID
	Run         func(context.Context) error
}

// Sweep runs every job with bounded fair concurrency, BLOCKING until all
// launched jobs finish or ctx is cancelled. It is the fleet-scale form of
// RunForTenant: the hibernation gate is consulted once per workspace (a dormant
// workspace's jobs are skipped), each workspace's concurrent jobs are capped by
// its MaxConcurrentSyncs budget, and total in-flight across the fleet is capped
// by the global ceiling — so one tenant's burst, or the whole fleet waking at
// once, cannot exhaust the DB pool / upstreams. Work that fits the budget runs
// in parallel; work that does not is deferred, not dropped.
//
// obs observes each job's terminal Outcome (and, for OutcomeRan, the job's own
// error) for metrics/logging. Because jobs run concurrently, obs MAY be invoked
// from multiple goroutines and so MUST be safe for concurrent use (a counter
// increment or a structured log line is fine). obs may be nil.
//
// A per-tenant-cap rejection is NOT a failure: that job is skipped this sweep
// (OutcomeSkippedBudget) and the caller is expected to re-enumerate it next
// tick — periodic work is idempotent and stays selected while still due. A
// cancelled ctx stops launching further jobs; already-launched jobs are still
// awaited.
//
// With a nil scheduler (degraded build) Sweep runs each job inline and
// unbounded, preserving "work still happens" over "work is bounded".
func (p *PeriodicRunner) Sweep(ctx context.Context, jobs []Job, obs func(Outcome, error)) {
	report := func(out Outcome, err error) {
		if obs != nil {
			obs(out, err)
		}
	}
	// Gate + cap are resolved once per workspace per sweep (a workspace can own
	// many jobs); the launch loop is single-goroutine so these caches need no
	// locking.
	gateCache := map[uuid.UUID]bool{}
	capCache := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		run, seen := gateCache[j.WorkspaceID]
		if !seen {
			run = p.shouldRun(ctx, j.WorkspaceID)
			gateCache[j.WorkspaceID] = run
		}
		if !run {
			report(OutcomeSkippedDormant, nil)
			continue
		}
		if p.sched == nil {
			report(OutcomeRan, j.Run(ctx))
			continue
		}
		capPerTenant, seen := capCache[j.WorkspaceID]
		if !seen {
			capPerTenant = p.maxPerTenant(ctx, j.WorkspaceID)
			capCache[j.WorkspaceID] = capPerTenant
		}
		release, err := p.sched.Acquire(ctx, j.WorkspaceID, capPerTenant)
		if err != nil {
			if ctx.Err() != nil {
				break // cancelled while waiting for a global slot
			}
			report(OutcomeSkippedBudget, nil) // per-tenant cap; retry next tick
			continue
		}
		wg.Add(1)
		go func(j Job, release func()) {
			defer wg.Done()
			defer release()
			report(OutcomeRan, j.Run(ctx))
		}(j, release)
	}
	wg.Wait()
}
