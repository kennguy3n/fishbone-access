# Scale & NoOps sizing — 5,000 SME tenants

This is the operator reference for running the ShieldNet Access control plane at
the product north star: **5,000 SME tenants under NoOps**, where a large fraction
are dormant trials that must cost ~nothing. It documents the recommended database
pool, outbound HTTP, and tenant-hibernation settings, with the rationale behind
each default so the numbers can be re-derived as the fleet grows.

All values are environment variables read by `internal/config`. The defaults
shipped in code are tuned for this 5,000-tenant case; override only when your
Postgres `max_connections` budget or measured load says so.

---

## 1. Database connection pool

### The constraint

Each binary (`ztna-api`, `access-connector-worker`, `access-workflow-engine`,
`pam-gateway`) owns **its own** pool, and each `ztna-api` replica also opens a
**secondary pgx pool** (`ACCESS_DB_PGX_MAX_CONNS`) for the GORM→pgx read paths.
So the connections a single process can hold against Postgres is:

```
per-process peak = ACCESS_DB_MAX_OPEN_CONNS + ACCESS_DB_PGX_MAX_CONNS
```

and the fleet total that must fit under Postgres `max_connections` (minus the
superuser reserve) is:

```
fleet peak = Σ over processes (replicas_p × per-process peak_p)
```

The number of **tenants does not appear** in this formula — that is the whole
point of the design. Connection demand scales with *concurrent in-flight work*,
not with how many tenants exist. Tenant hibernation (§3) keeps the dormant
majority from generating any periodic work, so they contribute **zero**
connection pressure.

### Recommended values (per process)

| Env var | Default | Rationale |
|---|---:|---|
| `ACCESS_DB_MAX_OPEN_CONNS` | `25` | Caps the GORM pool. 25 × API replicas is the dominant term; see budget below. |
| `ACCESS_DB_PGX_MAX_CONNS` | `8` | Secondary pgx pool for light, single-indexed read/append paths — sized small on purpose. |
| `ACCESS_DB_MAX_IDLE_CONNS` | `5` | Warm connections kept ready for the next request without re-dialing. |
| `ACCESS_DB_CONN_MAX_LIFETIME` | `30m` | Recycles connections so replicas pick up Postgres failovers and shed stale backend state. |
| `ACCESS_DB_CONN_MAX_IDLE_TIME` | `5m` | **NoOps lever** (API only): closes connections idle >5m so a quiet replica drops *below* `MAX_IDLE_CONNS`, returning capacity to Postgres on nights/weekends. |

### Worked budget for 5,000 tenants

A representative topology and its peak connection demand:

| Process | Replicas | Open + pgx | Peak conns |
|---|---:|---:|---:|
| `ztna-api` | 6 | 25 + 8 | 198 |
| `access-connector-worker` | 3 | 25 + 0 | 75 |
| `access-workflow-engine` | 2 | 25 + 0 | 50 |
| `pam-gateway` | 2 | 25 + 8 | 66 |
| **Total** | | | **389** |

Provision Postgres `max_connections` with headroom above the fleet peak:

```
max_connections ≥ fleet_peak / 0.8   →  ~490, round up to 500
```

(the `/0.8` leaves 20% for superuser/maintenance/migration connections). A
managed Postgres with `max_connections = 500` comfortably serves this fleet; the
500-tenant and 50-tenant stages below show how it scales down.

> **Scale down further with PgBouncer.** If you must run many more API replicas
> than the budget allows, front Postgres with a transaction-pooling proxy
> (PgBouncer) and treat `ACCESS_DB_MAX_OPEN_CONNS × replicas` as the *client*
> side; the proxy multiplexes onto far fewer server connections. The app pool
> bounds above are still correct — they just point at the proxy.

### Smaller stages (same formula)

| Stage | API replicas | Fleet peak | Suggested `max_connections` |
|---|---:|---:|---:|
| 50 tenants (pilot) | 2 | ~170 | 200 |
| 500 tenants | 3 | ~230 | 300 |
| 5,000 tenants | 6 | ~389 | 500 |

---

## 2. Outbound HTTP transport (connector fan-out)

Connectors fan out to a high cardinality of upstreams (one or more SaaS APIs per
tenant). Go's default `http.Transport` is tuned for a browser (2 idle conns per
host, 100 global) and would both throttle a busy host and leak connections
across thousands of hosts. `internal/services/access/httputil` installs **one
process-wide tuned transport** that every connector HTTP client shares, so the
whole fleet draws from a single bounded pool.

| Env var | Default | Rationale |
|---|---:|---|
| `ACCESS_HTTP_MAX_IDLE_CONNS` | `256` | Global idle ceiling across all upstreams — high enough to keep many tenants' connections warm. |
| `ACCESS_HTTP_MAX_IDLE_CONNS_PER_HOST` | `32` | Per-host idle pool, far above Go's default of 2, for shared upstreams hit by many tenants. |
| `ACCESS_HTTP_MAX_CONNS_PER_HOST` | `64` | Hard cap on total (active+idle) conns to one host, so one hot upstream can't monopolise sockets. |
| `ACCESS_HTTP_IDLE_CONN_TIMEOUT` | `90s` | Reclaims idle connections fast so a tenant that stops syncing leaves no lingering sockets. |
| `ACCESS_HTTP_TLS_HANDSHAKE_TIMEOUT` | `10s` | Bounds TLS setup to a slow/black-holed upstream. |
| `ACCESS_HTTP_DIAL_TIMEOUT` | `10s` | Bounds TCP connect. |
| `ACCESS_HTTP_FORCE_HTTP2` | `true` | Multiplexes many requests over one connection where the upstream supports H2, cutting socket count. |

**Interaction with hibernation:** because dormant tenants run no connector syncs
(§3), the transport's idle pool naturally drains for them and `IdleConnTimeout`
reclaims the sockets — the dormant majority hold no outbound connections.

---

## 3. Tenant hibernation (dormancy → near-zero cost)

`internal/services/tenancy` tracks per-tenant activity, classifies idle tenants
**dormant**, and lets periodic workers skip them. Dormant tenants wake **lazily**
on their next authenticated API call (no operator action). This is what makes a
dormant trial cost ~nothing: it runs no connector syncs, no reconcilers, no
scheduled work.

| Env var | Default | Rationale |
|---|---:|---|
| `ACCESS_TENANCY_HIBERNATION_ENABLED` | `true` | Master switch. `false` ⇒ every tenant treated active (activity is still recorded, so the feature can be turned on later with accurate history). |
| `ACCESS_TENANCY_DORMANT_IDLE` | `336h` (14d) | Idle threshold before a tenant is dormant — one trial-length of inactivity. |
| `ACCESS_TENANCY_RECONCILE_INTERVAL` | `15m` | How often the set-based dormancy sweep runs. The sweep is O(changed rows), so this is cheap even at 5,000 tenants. |
| `ACCESS_TENANCY_ACTIVITY_FLUSH` | `60s` | Per-tenant coalescing window for activity writes: a tenant hammering the API produces ~1 write/minute, not one per request. Must stay ≪ the idle threshold (enforced in code) so coalescing can never hide a wake. |
| `ACCESS_TENANCY_DEFAULT_TIER` | `trial` | Budget tier for tenants without an explicit budget row — the most-constrained tier, so an un-tiered tenant can never claim more than the smallest share. |

### Tiered resource budgets

Per-tenant concurrency budgets (migration `0019`, table `tenant_resource_budgets`)
bound how much periodic work any one tenant may run, so the dormant majority — or
a single noisy tenant — cannot starve paying tenants. A tenant with no row takes
its tier default:

| Tier | Max concurrent syncs | Max periodic jobs/hr | Fair-share weight |
|---|---:|---:|---:|
| `trial` | 1 | 4 | 1 |
| `base` | 2 | 12 | 2 |
| `pro` | 4 | 60 | 4 |
| `enterprise` | 8 | 240 | 8 |

The `tenancy.FairScheduler` enforces these per-tenant caps under a process-global
concurrency ceiling, so total background load is bounded regardless of how many
tenants wake at once.

### Wake latency

Wake is on the request hot path (the activity middleware records on every
authenticated, tenant-scoped call and flips the tenant active in the same write),
so the first request after dormancy wakes the tenant immediately; periodic work
resumes by the next reconcile tick at the latest. This latency is acceptable by
design — no request is ever blocked or dropped, only background work is deferred.
