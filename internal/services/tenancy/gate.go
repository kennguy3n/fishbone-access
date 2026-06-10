package tenancy

import (
	"context"

	"github.com/google/uuid"
)

// HibernationGate answers the one question every periodic worker (connector
// sync, scheduler, reconciler) should ask before doing work for a tenant:
// "should this tenant's periodic job run now?". Workers consult it to skip
// dormant tenants, which is what makes the dormant-trial majority cost ~nothing
// in steady state.
//
// Contract: the gate is FAIL-OPEN. A tenant that has never been classified, or
// any transient error, yields true (run). Hibernation only ever DEFERS work for
// a tenant the system is confident is dormant; it can never cause work to be
// silently dropped for an active tenant, so adopting the gate is always safe.
type HibernationGate interface {
	ShouldRunPeriodic(ctx context.Context, workspaceID uuid.UUID) (bool, error)
}

// AlwaysRun is the no-op gate: every tenant always runs. It is the correct gate
// when hibernation is disabled (config) or unavailable (degraded, no-DB boot),
// so callers can depend on a non-nil HibernationGate unconditionally.
type AlwaysRun struct{}

// ShouldRunPeriodic always returns true.
func (AlwaysRun) ShouldRunPeriodic(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

// Compile-time assertions that both the no-op gate and the real Service satisfy
// the interface.
var (
	_ HibernationGate = AlwaysRun{}
	_ HibernationGate = (*Service)(nil)
)
