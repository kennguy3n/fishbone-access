# How to build this, part 1: the shape of a multi-tenant access plane

The showcase posts (0–7) showed *what* fishbone-access does. This sub-series is
the *how*: enough architecture, data model, and wired build steps that a
technical-and-product pair could rebuild a system like it — and, just as
important, the **business decision** at each fork, seen through one lens we never
put down: **running SaaS security for up to 5,000 resource-light SME tenants with
no per-tenant ops**.

That lens is not decoration. It is the thing that makes this architecture differ
from the incumbents (CyberArk, SailPoint, Teleport, StrongDM), almost all of
which assume a customer with a platform team. We are building for the customer
who has *nobody* whose job is this.

## The product in one paragraph

A control plane that governs access — for SaaS apps, internal systems, and
privileged targets (SSH/database) — and emits a tamper-evident evidence chain an
auditor can re-verify. One tenant signs up, connects where their people log in,
writes a policy, and is producing defensible evidence the same day. No
appliances, no bastions to run, no integration project.

## Five binaries, one image

The whole system ships as **one container image** that can launch any of several
small Go binaries. That is a deliberate packaging decision (more on why below):

| Binary | Role |
| --- | --- |
| `cmd/ztna-api` | The HTTP control plane: workspaces, connectors, policies, access requests, PAM, discovery, compliance. Auth + tenant resolution live here. |
| `cmd/access-connector-worker` | Background queue worker: identity sync, access provisioning/revocation against connected systems. |
| `cmd/access-workflow-engine` | Background orchestrator: JML lifecycle, approval chains, scheduled certifications, rotation/retention/discovery sweeps. |
| `cmd/pam-gateway` | The multi-protocol privileged proxy (SSH / PostgreSQL / MySQL / k8s-exec / …) that records sessions and anchors them on the chain. |
| `cmd/access-target-agent` | The customer-side outbound connector agent: dials *out* over mTLS so we can reach private targets with zero inbound exposure. |

(There is also `cmd/access-ai-agent` for the request risk-scoring model and a
`cmd/migrate-lint` developer tool.) Only the agent runs on the customer's side;
everything else is ours to operate.

### Decision: one image, many binaries — not microservices

**The fork.** Split these into independently deployed services (the
"microservices" default), or ship one image that runs different entrypoints?

**What we chose.** One image, many binaries, sharing `internal/` packages and one
Postgres.

**Why, through the SME-at-scale lens.** Microservices buy you independent scaling
and team autonomy — both of which cost operational headcount we are explicitly
designing *out*. At 5,000 small tenants the bottleneck is never "the policy
service needs to scale separately from the connector service"; it is *cost per
tenant* and *number of moving parts an on-call human must understand*. One image
means one thing to build, scan, sign, and roll; the binaries still separate
concerns at the process level (the gateway's blast radius is not the API's), but
they share types and a test suite, so a change to the lease model can't drift
between a "lease service" and a "gateway service." Teleport and StrongDM run as
clusters you operate; CyberArk is a fleet. We made the opposite bet: **the
product is boring to run on purpose.**

## The request path

A normal authenticated API call walks a short, legible path:

```
client ──HTTPS──▶ ztna-api (Gin)
                   │
                   ├─ middleware: validate bearer token (iam-core JWKS / dev HMAC)
                   ├─ middleware: resolve tenant  → workspace_id in context
                   ├─ middleware: per-tenant rate limit + usage metering
                   ├─ handler   : authorize (RBAC) + validate input
                   ├─ service   : business logic (one workspace, always scoped)
                   └─ db        : Postgres, with RLS as the isolation backstop
```

Two things in that path are the spine of the whole design:

1. **Tenant resolution is middleware, not a handler concern.** By the time a
   handler runs, `workspace_id` is already in the request context and every query
   is scoped to it. A handler *cannot* accidentally serve cross-tenant data,
   because it never sees a request without a resolved tenant.
2. **Row-Level Security is a backstop, not the primary control.** Services scope
   every query themselves, *and* Postgres RLS (Post 9) refuses to return another
   tenant's rows even if a query forgets a `WHERE workspace_id =`. Belt and
   suspenders, because the cost of a multi-tenant isolation bug is the whole
   business.

## The background plane

Anything that is slow, scheduled, or must survive a request ending runs off the
API process:

- **The worker** (`access-connector-worker`) drains a job queue: a leaver kill
  switch fans out to every connector that supports deprovisioning; an access
  grant provisions downstream. Jobs are durable so a crash resumes, not drops.
- **The workflow engine** (`access-workflow-engine`) is the cron of the system:
  it advances JML runs, runs scheduled certifications, and drives the three
  sweeps the later posts cover — **rotation** (Post 11), **recording retention**,
  and **discovery** (Post 12). Each sweep is **hibernation-gated**: a tenant that
  is scaled-to-zero is skipped, not woken.

### Decision: scale-to-zero *per tenant*, with a sacrosanct fail-open gate

**The fork.** 5,000 tenants, most of them small and idle most of the day. Keep
every tenant's background machinery warm, or idle it?

**What we chose.** Per-tenant **hibernation**: an idle tenant's scheduled work is
suspended, and the gate that decides "is this tenant active?" **fails open** —
if the check itself errors, the tenant is treated as active and is *not* denied
service. Hibernation is a cost optimisation; it is never allowed to become an
availability bug.

**Why.** Idling idle tenants is the difference between a viable SME price and an
enterprise one. But the failure mode of an aggressive cost optimisation is
"we accidentally turned off a paying customer," which is fatal to trust. So the
rule is encoded everywhere the gate appears: **the optimisation may cost us
money when it errs; it may never cost the customer access.**

## Auth and identity

`ztna-api` validates a bearer token on every request — against an iam-core JWKS
endpoint in production (RS256/ES256, cached), or a dev HMAC secret locally — and
resolves it to a workspace. RBAC (owner / admin / security_admin / operator /
auditor) is enforced in handlers, and the highest-risk actions (policy promote,
evidence export, lease approval) additionally require **step-up MFA**: a fresh
RFC-6238 TOTP code with server-side anti-replay over a 30-second window.

### Decision: don't build an IdP

**The fork.** Identity is core to an access product. Build our own user
store / SSO, or integrate?

**What we chose.** Delegate authentication to iam-core (the identity service) and
own *authorization and governance*. We are not in the password-reset business.

**Why.** An SME already has an IdP (Google, Microsoft, Okta). The value we add is
not "another login"; it is what happens *after* login — the policy, the lease,
the evidence. Building an IdP would be a large surface with no differentiation
and a lot of liability. Integrate, and spend the complexity budget on the chain.

## What the rest of the sub-series builds

- **Post 9 — the data model:** the tables, the tenancy/RLS isolation model, the
  hash-chain evidence formula, and per-workspace key derivation.
- **Post 10 — the connector fabric:** the `AccessConnector` interface and optional
  capability interfaces that let 200+ providers share one code path.
- **Post 11 — the PAM workflow engine:** request → approval → time-boxed lease →
  recorded session → searchable replay, plus credential rotation.
- **Post 12 — discovery and governed onboarding:** three real discovery sources,
  reconcile, and an opt-in auto-onboard that never grants standing access.
- **Post 13 — cross-replica HA for the agent plane:** the durable session
  directory, epoch-CAS ownership, and the mTLS forward plane.

Every one ends the same way the showcase posts do: with the business decision
that shaped it, and an honest note on where an incumbent is still the heavier
tool.

---

*Next: [Post 9 — the data model](09-data-model.md).*
