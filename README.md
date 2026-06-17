# ShieldNet Access (fishbone-access)

Zero Trust Access + Privileged Access Management (PAM) for SMEs. ShieldNet
Access provides per-application access governance, identity-provider
connectors, an access-request lifecycle with policy-driven approvals, and a
multi-protocol PAM gateway — built to run cheaply across three deployment
tiers (single-server → managed K8s → full production) with no dedicated IT.

Identity and tenancy are delegated to [**uneycom/iam-core**](https://github.com/uneycom/iam-core)
(OAuth2/OIDC, social login, MFA). ShieldNet Access validates iam-core access
tokens and maps each iam-core tenant to an isolated workspace. See
[docs/iam-core-integration.md](docs/iam-core-integration.md) for the integration
contract.

## Architecture

Four Go binaries share one image:

| Binary | Role |
| --- | --- |
| `cmd/ztna-api` | HTTP API: workspaces, connectors, access requests, policies. iam-core bearer-token auth + tenant resolution. |
| `cmd/access-connector-worker` | Background queue worker: identity sync, access provisioning/revocation. |
| `cmd/access-workflow-engine` | Background workflow orchestrator: JML lifecycle, approval chains, scheduled access certifications. |
| `cmd/pam-gateway` | Multi-protocol PAM proxy (SSH/PostgreSQL/MySQL/Kubernetes-exec) with session recording + audit hash chain. |

Internal packages:

- `internal/config` — 12-factor environment configuration.
- `internal/iamcore` — iam-core JWT validator (JWKS) + Management API client.
- `internal/middleware` — Gin auth + tenant-resolution middleware.
- `internal/models` — GORM models for the ten core tables.
- `internal/migrations` — embedded, idempotent SQL migration runner.
- `internal/services/access` — `AccessConnector` interface, optional capability
  interfaces, and the connector registry.
- `internal/handlers` — HTTP routing (health/readiness + authenticated API).
- `internal/workers` — generic job-drain loop behind the worker binary.
- `internal/gateway` — PAM listener supervisor behind the gateway binary.
- `internal/pkg/{crypto,database,logger}` — AES-GCM secret sealing, GORM
  connection, slog logger.

## Quick start

```bash
# Run the full single-server stack (Postgres + Redis + 4 services).
docker compose up --build --wait

# Or run the API directly (degraded mode without Postgres/iam-core).
go run ./cmd/ztna-api
```

### Configuration

| Env var | Purpose |
| --- | --- |
| `ACCESS_HTTP_ADDR` | API listen address (default `:8080`). |
| `ACCESS_DATABASE_URL` | Postgres DSN. Unset → degraded mode. |
| `ACCESS_REDIS_URL` | Redis URL for the worker queue. |
| `ACCESS_CREDENTIAL_DEK` | base64 32-byte AES-256 key sealing connector secrets. Unset (and no `ACCESS_KMS_MASTER_KEY`) → secret persistence fails closed. |
| `ACCESS_KMS_MASTER_KEY` | base64 32-byte master key for per-workspace keys. When set, a distinct DEK is derived per workspace (HKDF) and this takes precedence over `ACCESS_CREDENTIAL_DEK`. |
| `ACCESS_KMS_KEY_VERSION` | Current key version new writes seal under (default `1`); bump to rotate while old rows still open under their recorded version. |
| `ACCESS_TENANT_RATE_LIMIT_ENABLED` | Per-tenant inbound rate limiting on the authenticated API (default `true`). |
| `ACCESS_TENANT_RATE_LIMIT_RPS` | Sustained requests/sec per tenant (default `50`). |
| `ACCESS_TENANT_RATE_LIMIT_BURST` | Instantaneous per-tenant bucket depth (default `100`). |
| `ACCESS_USAGE_METERING_ENABLED` | Per-tenant usage metering (cost-to-serve attribution) on the authenticated API (default `true`). |
| `ACCESS_USAGE_METERING_FLUSH_INTERVAL` | How often in-memory per-tenant counts are flushed to the `tenant_usage` rollup (default `30s`). |
| `IAM_CORE_ISSUER` | iam-core base URL (derives JWKS + discovery). Unset → authenticated API returns 503. |
| `IAM_CORE_CLIENT_ID` / `IAM_CORE_CLIENT_SECRET` | Confidential OAuth2 client for SSO + management. |
| `IAM_CORE_AUDIENCE` | Expected `aud` claim on access tokens. |
| `ACCESS_PG_KERBEROS_ENABLED` | Enable upstream GSSAPI/Kerberos auth from the Postgres proxy to clusters whose `pg_hba` demands `gss` (default `false`). |
| `ACCESS_PG_KERBEROS_KEYTAB` | Path to the gateway's keytab holding the service principal's keys. Required when Kerberos is enabled. |
| `ACCESS_PG_KERBEROS_PRINCIPAL` | The gateway's Kerberos principal in `user@REALM` form (e.g. `shieldnet-gw@EXAMPLE.COM`). Required when enabled. |
| `ACCESS_PG_KERBEROS_KRB5_CONF` | krb5.conf describing the realm/KDC topology (default `/etc/krb5.conf`). |
| `ACCESS_PG_KERBEROS_SERVICE` | Default Kerberos service name for the upstream SPN when a target does not name one (default `postgres`). |

#### Postgres upstream Kerberos (GSSAPI)

The operator hop into the PAM gateway always stays on the one-shot connect token
over TLS; the gateway declines operator-side GSS *encryption* in favour of TLS
(equivalent, and what pgbouncer does). What this enables is upstream
*authentication*: when the env vars above are set, the gateway logs in once with
its keytab principal and authenticates to a target cluster's `gss` `pg_hba` rule
via SPNEGO/Kerberos instead of a vault password. The KDC login is lazy (deferred
to the first such connection), so a KDC outage degrades only Kerberos targets
rather than failing gateway boot.

A target opts in through its `config` JSON:

- `auth_mode`: `kerberos` (or `gssapi`) — use the gateway's service ticket
  instead of the stored password.
- `krb_spn`: explicit service principal name, e.g. `postgres/db.example.com`.
  When set it wins; otherwise the SPN is built as `<service>/<target-host>`.
- `krb_service`: per-target override of `ACCESS_PG_KERBEROS_SERVICE` for the
  SPN's service component.

#### Credential encryption keys

One key roots all at-rest secrets (connector credentials and TOTP step-up MFA).
Precedence is: `ACCESS_KMS_MASTER_KEY` (per-workspace derived DEKs) → `ACCESS_CREDENTIAL_DEK`
(single static DEK) → none (secret persistence + MFA fail closed). Pick exactly
one for a steady-state deployment:

- **New deployment:** set `ACCESS_KMS_MASTER_KEY` only. Every workspace gets a
  distinct derived DEK (tenant key separation) and MFA secrets seal under a key
  derived from the same master.
- **Legacy deployment:** keep `ACCESS_CREDENTIAL_DEK` only (single shared DEK).

**Migrating static DEK → per-workspace master key.** The master key takes
precedence the moment it is set, and the two key hierarchies are independent, so
secrets sealed under the static DEK do **not** transparently open under the
master key. Setting **both** is therefore a re-seal migration, not a drop-in
swap — the binaries log a loud boot warning while both are present. To migrate:

1. Set `ACCESS_KMS_MASTER_KEY` alongside the existing `ACCESS_CREDENTIAL_DEK`.
2. Re-save each connector's secret (and re-enrol TOTP MFA) so it is re-sealed
   under the master-derived key. Until a secret is re-sealed it will fail to
   open.
3. Once everything is re-sealed, remove `ACCESS_CREDENTIAL_DEK` and the warning
   clears.

If there is no existing sealed data, skip the overlap entirely: set only
`ACCESS_KMS_MASTER_KEY` from the start.

#### Per-tenant rate limiting

The authenticated `/api/v1` surface caps the inbound request rate **per tenant**
(keyed on the verified `tenant_id`, after tenant resolution), so one noisy or
runaway tenant cannot monopolise the shared Postgres pool — or our bill — at the
expense of the other tenants. Over-budget requests get `429 Too Many Requests`
with a `Retry-After` header; throttle events are exported as
`shieldnet_http_requests_throttled_total{route=...}` on `/metrics` (by route
template, never by tenant id, to bound cardinality).

The limiter is a token bucket per tenant: `ACCESS_TENANT_RATE_LIMIT_RPS` is the
sustained refill rate and `ACCESS_TENANT_RATE_LIMIT_BURST` the instantaneous
depth. By default it is **in-memory and therefore per-replica** — with `N`
ztna-api replicas a tenant's effective ceiling is `N × RPS`. That is the
no-extra-infrastructure posture and already bounds a single abusive tenant to a
small multiple of the rate.

For a **globally exact** limit across replicas, set `ACCESS_REDIS_URL` and
`ACCESS_TENANT_RATE_LIMIT_SHARED_STORE=true`: the limiter then becomes a
**Redis-backed atomic token bucket**, so a tenant's ceiling is `RPS` across the
whole fleet rather than `N × RPS`. The admission decision (refill, check,
consume) runs as a single server-side Lua script (`EVALSHA`, one round trip), so
two replicas hitting the same tenant in the same instant cannot both over-admit
against the shared budget — the exactness guarantee is enforced inside Redis,
not approximated per replica. The trade-off is one Redis round trip on the
admission path of every request (versus a lock-and-map with no I/O before). It
is **fail-open**: if Redis is unreachable, slow, or errors, the limiter *admits*
rather than failing the tenant's request, so a flapping Redis reverts to the
permissive posture and never takes down request serving (a degraded backend is
visible as `shieldnet_sharedstore_fail_open_total{subsystem="ratelimit"}`). The
flag is only honoured when `ACCESS_REDIS_URL` is set; otherwise the limiter
falls back to the in-memory bucket and logs a startup warning. The middleware
and its `RateLimiter` interface are unchanged — only the construction site in
`cmd/ztna-api` chooses the backend. Set `ACCESS_TENANT_RATE_LIMIT_ENABLED=false`
to disable rate limiting entirely.

#### Per-tenant usage metering

The rate limiter above is the "cap the abuser" half of the cost story; usage
metering is the **"who is using what"** half. Every authenticated, tenant-scoped
request increments a per-tenant counter (`api_requests` today) so cost-to-serve
is **attributable per tenant** across the fleet and can later be billed or
capped. A tenant reads its own current-period consumption from the
authenticated `GET /api/v1/usage` endpoint (gated by the `usage.read`
permission, owner/admin only).

**Cardinality is the operative constraint** at 5,000 tenants, so this is the
one place where we deliberately do **not** use a Prometheus label. A per-tenant
label would explode the time-series count (tenants × routes), so per-tenant
attribution lives in Postgres — a `tenant_usage` row per
`(workspace_id, period, metric)`, where the period is a billing month
(`YYYY-MM` UTC) — and only the **aggregate**, non-tenant-labelled counter
`shieldnet_usage_events_total{metric=...}` reaches `/metrics` for operator
dashboards. Per-tenant numbers are read back through the authenticated endpoint,
never scraped per tenant.

Counts accumulate **in memory** and flush to the rollup every
`ACCESS_USAGE_METERING_FLUSH_INTERVAL` (and once more on graceful shutdown). The
hot path is a single map increment; the database write happens off the request
path in a background goroutine, and is **fail-open** — a nil aggregator or an
unresolved tenant lets the request through untouched, exactly like the
rate-limit middleware. Memory is bounded by the **active-tenant working set**
(each flush drains the buffer), so an idle tenant costs nothing.

Like the limiter the aggregator is **in-memory and therefore per-replica**, but
here that needs no shared store to be *correct*: each replica flushes its own
deltas with an **additive UPSERT** (`count = count + delta`), so `N` replicas
sum into one row rather than overwriting one another. The trade-off is
durability granularity, not accuracy — a replica that crashes loses at most its
last unflushed window. Set `ACCESS_USAGE_METERING_ENABLED=false` to disable it
entirely (the pre-feature behaviour).

#### Per-tenant billing: statements + quota enforcement

Metering answers "who is using what"; billing is the **economics layer on top**:
"what may a tenant consume, and what does it owe". It adds two things, both
derived from the **same** `tenant_usage` rollup the meter writes (no second
source of truth for consumption):

- **Statements.** `GET /api/v1/billing/statement` (optionally `?period=YYYY-MM`)
  returns a periodized, per-metric statement — included quota, usage, overage,
  and the integer amount that overage costs — plus the plan's base price and the
  period total. Generation is a **pure function** of `(workspace, period, plan,
  rollup rows)` with **no wall-clock field**: for a **fixed plan** and the
  period's immutable rollup rows it yields a byte-identical statement (the
  idempotency contract). The plan is resolved **live** (there is no plan-history
  snapshot), so re-pricing a closed period under a tenant's new plan after an
  upgrade/downgrade is by design, not a determinism break. All counts and amounts
  are **integers** (minor units), so money never carries float drift.
- **Quota enforcement.** A fail-open middleware, mounted right *before* the meter
  (so a hard-denied request is rejected before it is counted as billable usage)
  and keyed by the resolved workspace UUID, classifies each tenant against its
  plan: **soft** (over the included allowance — allowed, but flagged via
  `X-Quota-State`/`X-Quota-Metric` headers and metered, and billed as overage)
  and **hard** (at/over the plan's ceiling). A hard breach is rejected with
  **HTTP 402 Payment Required** — chosen over 429 because the breach is a
  plan/period allowance, not a per-second rate (429 is the rate limiter's
  status), so a client can distinguish "slow down" from "your plan's allowance
  for the period is exhausted, upgrade to continue". The check runs **before**
  the handler, so a denied request never reaches Postgres or other expensive
  shared work — the whole point is protecting shared resources and the bill.

**Plans reuse the tenancy tier ladder** (`trial`/`base`/`pro`/`enterprise`)
rather than inventing a parallel billing taxonomy. The assignment lives in a
separate `tenant_plan` table keyed by `workspace_id` (workspace-scoped, under
the same RLS regime as the rest of the tenant data): it stays distinct from
`tenant_resource_budgets` because that table bounds *internal* background-work
concurrency while `tenant_plan` bounds *external* request consumption and
carries the billing overrides — the shared tier string ties them to one ladder
without coupling two concerns behind one row. Like the budgets, **absence of a
row means the tenant takes its plan's built-in quota ladder** (the quota ladders
and integer pricing live in code, `internal/services/billing`), so the table
stays near-empty for the dormant-trial majority; a zero override column means
"inherit the plan default". An owner assigns its own plan via
`PUT /api/v1/billing/plan`. The reads are gated by `billing.read` (owner/admin,
exactly like `usage.read`); the plan write by `billing.manage` (owner-only, like
`workspace.manage`) — selecting a plan sets what a tenant owes, an
account-lifecycle decision.

The enforcement decision is **cached per workspace for `ACCESS_BILLING_CACHE_TTL`**
(default 30s), so the common path is a pure in-memory map read — enforcement adds
**no per-request DB load**. The cache is in-memory and therefore **per-replica**,
like the limiter and the meter; combined with the meter's flush interval, the TTL
is the bounded window over which replicas converge on fresh usage. An idle
tenant's entry is evicted by a background janitor, bounding memory to the
active-tenant set. The whole subsystem is **fail-open** at every step — a nil
service, an unresolved tenant, or a lookup error proceeds untouched — so a
billing outage degrades to "no enforcement", never an API outage.

Billing is **disabled by default** (`ACCESS_BILLING_ENABLED`): unlike metering it
can reject requests, so it is opt-in, and it requires metering to be on (with it
off the rollup never advances and statements show only the base price). Hard
enforcement is **separately gated** by `ACCESS_BILLING_ENFORCE_HARD_CAP`, also
off by default: the safe rollout at 5,000 tenants is **shadow mode** — detect and
surface breaches (headers + the `shieldnet_billing_quota_breaches_total{state,route}`
aggregate counter) without rejecting — so an operator can observe who *would* be
capped before flipping enforcement on.

Setting `ACCESS_REDIS_URL` and `ACCESS_USAGE_METERING_SHARED_STORE=true`
**consolidates** the rollup through a shared Redis accumulator: instead of every
replica writing the same `(workspace, period, metric)` row each window, the
per-replica deltas are first summed into one Redis counter (`HINCRBY`), and a
single **claim-based flush** rolls that global counter up into `tenant_usage`.
The claim is an atomic `HGETALL`+`DEL` in one Lua script, so when multiple
replicas' flushers race, exactly one reads the counters and the rest see an
empty hash — no double counting. The hot path is unchanged (recording is still
the in-memory increment) and Postgres stays the durable record. It is
**fail-open**: if Redis is down the sink degrades the deltas to the Postgres
path (the same per-replica UPSERT) or, failing that, drops them — usage is
best-effort telemetry and never blocks a request (a degraded backend shows as
`shieldnet_sharedstore_fail_open_total{subsystem="usage"}`). The flag is only
honoured when `ACCESS_REDIS_URL` is set; otherwise metering keeps the
per-replica UPSERT and logs a startup warning.

#### Tenant hibernation (scale-to-zero per tenant)

Most of a 5,000-tenant fleet are **dormant trials**. Hibernation makes that
majority cost ~nothing in steady state by letting the periodic workers **skip**
tenants that are confidently idle, while keeping the system safe for everyone
else.

End-to-end mechanism:

1. **Record activity.** ztna-api's request-path middleware records per-tenant
   activity (login / API / provisioning). Writes are coalesced
   (`ACCESS_TENANCY_ACTIVITY_FLUSH`) so a busy tenant is a single periodic write,
   not one per request. Activity is recorded **whenever a DB is present,
   independent of whether hibernation is enabled**, so the feature can be turned
   on later with accurate history.
2. **Classify dormant on idle.** A set-based reconcile sweep
   (`ACCESS_TENANCY_RECONCILE_INTERVAL`) marks any tenant whose last activity
   predates `ACCESS_TENANCY_DORMANT_IDLE` as **dormant**, and seeds rows for
   tenants provisioned before the subsystem existed. It is three SQL statements
   in one transaction — cost is O(changed rows), not O(tenants) — so it stays
   cheap at fleet scale and is safe to run on every replica (it converges the
   same state).
3. **Workers skip dormant tenants.** Before doing a tenant's **periodic** work,
   each worker asks the gate `ShouldRunPeriodic(ctx, workspaceID)` and skips when
   it returns false. Two loops gate today:
   - `access-connector-worker` — the periodic **identity sync**
     (`JobTypeSyncIdentities`) only. On-demand provision/revoke (JML actions) are
     **never** gated.
   - `access-workflow-engine` — the periodic **certification review sweep**, per
     workspace, at enqueue time.
   A skipped sync is **deferred, not dropped**: the job is acked and the
   delta-sync cursor is untouched, so the next cycle after the tenant wakes
   resumes exactly where it would have.
4. **Wake on activity.** The next real activity from a dormant tenant flips it
   back to active immediately (a single conditional `dormant→active` update on
   the request path), so its very next periodic cycle runs — there is **no
   missed-wake window**. The reconcile sweep is a secondary backstop wake.

**Fail-open guarantee (sacrosanct).** The gate may only ever *defer* work for a
tenant the system is **confident is dormant**. A never-classified tenant, a
tenant with no activity row yet, or **any error** yields *run*. Hibernation can
never silently drop or skip work for an active or unclassified tenant. Every
gate check in the workers honours this, so adopting the gate is always safe.

**What "scale-to-zero per tenant" does and does NOT mean here.** It **defers
per-tenant periodic work** (connector syncs, scheduled review sweeps) for
dormant tenants. It is **not** pod scale-to-zero: the worker processes keep
running and keep serving every active tenant; we simply stop spending periodic
compute on the dormant majority. On-demand, user-facing actions are never
gated.

**Worker context & RLS.** The periodic workers run in **worker context** — there
is no per-request tenant bound on the context, so Postgres RLS is permissive
rather than request-scoped. Consulting the gate is correct under that model: the
gate read is a **workspace-scoped primary-key lookup** (`WHERE workspace_id = ?`)
that binds the tenant explicitly and returns **no tenant data** — only an
operational classification (`dormant`/`active`) and, for the gauge, an unscoped
`COUNT` of the state column. It therefore cannot widen or break tenant
isolation. The workers deliberately **record no activity of their own**: doing
scheduled work for a tenant must not itself count as that tenant's activity, or a
hibernated tenant could never stay dormant. ztna-api (the request path) owns
activity recording and the reconcile sweep; the workers only *read* the gate.

**Disabled mode.** `ACCESS_TENANCY_HIBERNATION_ENABLED=false` degrades cleanly to
`AlwaysRun` **everywhere, including the workers** (each constructs the no-op gate
instead of the DB-backed service, so there are no gate DB reads), while ztna-api
still records activity. This is the pre-feature behaviour with history
accumulating for a later enable.

**Observability.** The savings are provable from aggregate, **never
tenant-labelled** Prometheus series (preserving the cardinality discipline of the
usage metering above):

- `shieldnet_hibernation_tenants_dormant` (gauge) — fleet-wide dormant count,
  refreshed every reconcile sweep from the authoritative state column (so it is
  self-correcting). This is the headline scale-to-zero signal.
- `shieldnet_hibernation_periodic_jobs_skipped_total{worker}` (counter) — periodic
  jobs skipped because the tenant was dormant, by worker (`connector_sync`,
  `review_sweep`). Every increment is realized work *not* done.
- `shieldnet_hibernation_wake_events_total` (counter) — lazy `dormant→active`
  wakes driven by real activity (once per transition, not per request).

ztna-api exposes these on its existing `/metrics`; the background workers serve a
minimal `/metrics` + `/healthz` of their own on `ACCESS_WORKER_METRICS_ADDR`
(default `:9090`, set empty to disable) because the skip counter increments
inside them.

## Deployment

The single-server tier runs via [`docker-compose.yml`](docker-compose.yml)
(`docker compose up --build --wait`). For Kubernetes — the managed-K8s and full
production tiers — use the Helm chart and plain manifests under
[`deploy/`](deploy):

```bash
helm install sa deploy/helm/shieldnet-access -n shieldnet-access --create-namespace \
  -f deploy/helm/shieldnet-access/examples/production.values.yaml
# ...or, without Helm:
kubectl apply -f deploy/k8s/
```

The chart surfaces the full `ACCESS_*` config via a ConfigMap, routes the DB
DSN / KMS master key / credential DEK through a referenced Secret (or your own
`existingSecret`), and gates Ingress, HPA, a Prometheus `ServiceMonitor`, and an
optional bundled dev Postgres behind values flags. See
[`deploy/README.md`](deploy/README.md) for the required secrets, the
external-vs-bundled Postgres choice, and scaling guidance
([`deploy/SCALE_SIZING.md`](deploy/SCALE_SIZING.md)).

## Development

```bash
make build   # go build ./...
make test    # go test -race ./...
make lint    # go vet + golangci-lint
make ci      # full local CI gate
```

## What's included

This repository is the complete control plane:

- The foundation — config, iam-core integration, models, migrations,
  middleware, the connector registry, and the worker/gateway supervisors.
- The 200+ connector catalogue and the access-request lifecycle with its
  policy engine.
- The multi-protocol PAM gateway, plus the AI risk agent and the workflow
  engine.
- The Kubernetes deployment artifacts (Helm chart + plain manifests) under
  [`deploy/`](deploy).
- The Android and iOS client SDKs under [`sdk/`](sdk).
