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

// RunForTenant runs job for one tenant iff it is awake and a fair-scheduling
// slot is available within the tenant's budget:
//
//   - dormant tenant            → (OutcomeSkippedDormant, nil), job not called
//   - at concurrency budget     → (OutcomeSkippedBudget, nil), job not called
//   - otherwise                 → (OutcomeRan, job(ctx)), slot released after
//
// A gate error is treated fail-open (the job runs): deferring real work because
// a classification read hiccuped would be worse than running it.
func (p *PeriodicRunner) RunForTenant(ctx context.Context, workspaceID uuid.UUID, job func(context.Context) error) (Outcome, error) {
	if p.gate != nil {
		run, err := p.gate.ShouldRunPeriodic(ctx, workspaceID)
		if err == nil && !run {
			return OutcomeSkippedDormant, nil
		}
		// err != nil ⇒ fail open and fall through to run.
	}

	maxPerTenant := 0
	if p.budgets != nil {
		if b, err := p.budgets.BudgetFor(ctx, workspaceID); err == nil {
			maxPerTenant = b.MaxConcurrentSyncs
		}
		// On a budget read error, fall back to no per-tenant cap; the global
		// ceiling still bounds total work.
	}

	if p.sched != nil {
		release, ok := p.sched.TryAcquire(workspaceID, maxPerTenant)
		if !ok {
			return OutcomeSkippedBudget, nil
		}
		defer release()
	}

	return OutcomeRan, job(ctx)
}
