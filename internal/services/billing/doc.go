// Package billing is the per-tenant economics layer that sits ON TOP of the
// usage-metering rollup (internal/services/usage). Metering answers "who is
// using what"; billing answers the two questions that turn that into money and
// protection: "what does a tenant OWE for a period" (statements) and "what may
// a tenant CONSUME before it is capped" (quota enforcement).
//
// It owns three cooperating concerns, all keyed on the workspace UUID that is
// the platform's tenant-isolation boundary:
//
//   - Plans. A tenant's PLAN names which quota ladder and pricing apply. The
//     plan identity is deliberately the SAME tier ladder as the tenancy
//     resource budgets (tenancy.TierTrial/Base/Pro/Enterprise), reusing those
//     constants rather than inventing a parallel billing taxonomy. The two stay
//     in SEPARATE tables because they answer different questions on different
//     cadences — tenant_resource_budgets bounds INTERNAL background-work
//     concurrency for the fair scheduler, tenant_plan bounds EXTERNAL request
//     consumption and carries billing quota overrides — while the shared tier
//     string ties them to one ladder. Absence of a plan row means the tenant
//     takes the tier-default ladder (planDefaults), so the table holds only
//     explicit assignments/overrides and stays near-empty for the dormant-trial
//     majority, exactly like the budget table.
//
//   - Statements. Given a tenant and a period, Statement derives a structured,
//     line-item statement from the tenant_usage rollup and the tenant's plan:
//     per metric the included quota, the used count, the overage, and an
//     integer amount in minor units (no float drift). It reads the SAME rollup
//     the meter writes — there is no second source of truth for consumption —
//     and is DETERMINISTIC: generation carries no wall-clock field, so for a
//     FIXED plan and the period's immutable rollup rows it yields a
//     byte-identical statement. The plan is resolved LIVE (there is no
//     plan-history snapshot), so re-pricing a closed period under a tenant's new
//     plan after an upgrade/downgrade is by design, not a determinism break.
//
//   - Quota enforcement. A fail-open, TTL-cached decision ("is this tenant over
//     its included quota / hard ceiling?") consumed by an enforcement
//     middleware mounted on the tenant-scoped group. SOFT (over the included
//     quota) allows the request but flags it via a response header and a
//     metered counter; HARD (over the hard ceiling) rejects with 402 Payment
//     Required BEFORE the request reaches Postgres or any expensive work. The
//     decision is cached per workspace with a short TTL so enforcement adds no
//     DB read per request, and the cache is per-replica and TTL-bounded so
//     replicas converge — the same posture as the rate limiter and the meter.
//
// The package is decoupled from its transport: Service depends on a small
// UsageReader interface (satisfied by *usage.Store) and a Store for plans, and
// the middleware depends only on the QuotaEnforcer interface, so both are
// testable with fakes. Production wires it from cmd/ztna-api behind
// ACCESS_BILLING_* config; the schema lives in migration 0026_tenant_plan.
package billing
