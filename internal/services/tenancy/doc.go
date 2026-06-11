// Package tenancy makes the ShieldNet Access control plane scale to thousands
// of SME tenants under a NoOps operating model, where a large fraction are
// dormant trials that must consume near-zero periodic compute and storage.
//
// It owns three cooperating concerns, all keyed on the workspace UUID that is
// the platform's tenant-isolation boundary:
//
//   - Activity tracking & dormancy classification. Every real tenant
//     interaction (an authenticated API call, a login, a connector sync)
//     records a last-activity timestamp via an ActivityRecorder. A periodic,
//     set-based Reconcile sweep classifies each tenant active vs dormant from a
//     configurable idle threshold (e.g. a 14-day trial window). Writes are
//     coalesced per tenant so sustained load does not amplify into per-request
//     writes — essential at 5,000 tenants.
//
//   - Hibernation / scale-to-zero. Dormant tenants are excluded from periodic
//     background work (connector syncs, schedulers, reconcilers) through the
//     HibernationGate interface — "should this tenant's periodic job run now?".
//     The gate is read-through and fail-open: a tenant with no classification
//     yet, or any error, is allowed to run, so the optimisation can never cause
//     a correctness regression (no data loss, only deferred work). A tenant
//     wakes LAZILY and idempotently on its first real activity, so wake latency
//     is bounded by the activity-flush window, not the reconcile interval.
//
//   - Tiered resource budgets & fair scheduling. Per-tier caps (and optional
//     per-workspace overrides) bound how much concurrent periodic work any one
//     tenant may run, so a noisy or dormant tenant cannot starve an active one.
//     A FairScheduler hands out per-tenant concurrency slots under a global
//     ceiling, weighting by tier, so background work is shared fairly across
//     the fleet rather than first-come-first-served.
//
// The package is deliberately decoupled from the periodic workers it serves:
// it exposes interfaces (HibernationGate, ActivityRecorder) and a PeriodicRunner
// helper that callers consult, rather than reaching into connector, lifecycle,
// or PAM code. Production wires it from cmd/ztna-api; the schema lives in
// migrations 0018 (tenant activity) and 0019 (tenant resource budgets).
package tenancy
