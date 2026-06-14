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
depth. It is **in-memory and therefore per-replica** — with `N` ztna-api
replicas a tenant's effective ceiling is `N × RPS`. That is the deliberate
local/dev posture (no extra infrastructure) and already bounds a single abusive
tenant to a small multiple of the rate; a globally exact limit across replicas
would use a shared store via `ACCESS_REDIS_URL`, which the limiter interface is
designed to accept later without call-site changes. Set
`ACCESS_TENANT_RATE_LIMIT_ENABLED=false` to disable it entirely.

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

## Roadmap

This repository is built in sessions. 1A (this scaffold) ships the foundation:
config, iam-core integration, models, migrations, middleware, the connector
registry, and the worker/gateway supervisors. Subsequent sessions add the 200+
connectors (1B), the access-request lifecycle and policy engine (1C), the full
PAM implementation (1D), and the AI agent and workflow engine (1E). The
Kubernetes deployment artifacts (Helm chart + plain manifests) live under
[`deploy/`](deploy); the client SDKs land in a later session (1F).
