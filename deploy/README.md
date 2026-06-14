# Deploying ShieldNet Access

This directory holds the Kubernetes deployment artifacts for the ShieldNet
Access control plane:

| Path | What it is |
|---|---|
| [`helm/shieldnet-access/`](helm/shieldnet-access) | Production-leaning Helm chart (recommended). |
| [`k8s/`](k8s) | Plain, apply-able manifests for a minimal install without Helm. |
| [`SCALE_SIZING.md`](SCALE_SIZING.md) | Connection-pool / replica / hibernation sizing for the 5,000-SME-tenant target. |

Both deploy the same four binaries from the single multi-binary image (the
[`Dockerfile`](../Dockerfile)), each selected by its container `command`:

| Component | Binary | Surface |
|---|---|---|
| `ztna-api` | `ztna-api` | REST API / control plane — HTTP `:8080` with `/health`, `/readyz`, Prometheus `/metrics`. Runs DB migrations at startup. |
| `pam-gateway` | `pam-gateway` | Protocol-aware proxy (SSH `:2222`, Postgres `:5432`, MySQL `:3306`, k8s-exec `:8443`, RDP, VNC, Mongo, Redis, MSSQL, HTTP). No HTTP health endpoint — probed via TCP on the SSH listener. |
| `access-connector-worker` | `access-connector-worker` | Drains identity-sync / provision / revoke jobs. No HTTP surface. |
| `access-workflow-engine` | `access-workflow-engine` | JML lifecycle, approvals, scheduled certifications. No HTTP surface. Requires a credential key to boot. |

> The image publishes no public tag — build and push it yourself from the repo
> root: `docker build -t <repo>:<tag> . && docker push <repo>:<tag>`, then set
> `image.repository` / `image.tag` (chart) or edit the manifests (`k8s/`).

## Prerequisites

- Kubernetes 1.25+ and `kubectl`.
- [Helm](https://helm.sh) 3.x (for the chart path).
- A **PostgreSQL** database (the only datastore). External managed Postgres is
  the production posture; a bundled dev Postgres is available behind a flag.
- For `observability.serviceMonitor.enabled`: the Prometheus Operator CRDs.

## Configuration model

Configuration is entirely via `ACCESS_*` / `PAM_*` / `IAM_CORE_*` / `OTEL_*`
environment variables (see [`internal/config/config.go`](../internal/config/config.go)
and [`.env.example`](../.env.example)). The chart splits them:

- **Non-secret** values → a **ConfigMap** (`config.*` and `observability.*` in
  `values.yaml`).
- **Secret** values → a **Secret**, referenced (never baked into the ConfigMap).

### Required secrets

| Key | Purpose |
|---|---|
| `ACCESS_DATABASE_URL` | Postgres DSN (carries the DB password). Without it, `ztna-api` boots in **degraded** mode (authenticated API returns 503) and the workers/gateway don't serve. |
| `ACCESS_KMS_MASTER_KEY` **or** `ACCESS_CREDENTIAL_DEK` | base64 32-byte key (`openssl rand -base64 32`). `KMS_MASTER_KEY` is preferred (per-workspace DEK via HKDF). `access-workflow-engine` refuses to start without one of these; connector secrets fail closed. |

### Optional secrets

`ACCESS_REDIS_URL`, `IAM_CORE_CLIENT_SECRET`, `ACCESS_AI_AGENT_API_KEY`,
`AUTH_JWT_SECRET` (non-prod dev auth only), `PAM_SSH_HOST_KEY` (set this for a
**stable SSH host-key fingerprint** across `pam-gateway` replicas — otherwise
each pod TOFUs an ephemeral key), `PAM_SSH_CA_KEY`.

## Helm: production install (external Postgres, recommended)

Manage secrets **out-of-band** (ExternalSecrets / SealedSecrets / sops) so real
values are never templated into the release, then point the chart at that
Secret with `secrets.existingSecret`:

```bash
# 1. Create the Secret (or have ExternalSecrets reconcile it).
kubectl create namespace shieldnet-access
kubectl -n shieldnet-access create secret generic shieldnet-access-prod \
  --from-literal=ACCESS_DATABASE_URL='postgres://user:pass@db.internal:5432/shieldnet_access?sslmode=require' \
  --from-literal=ACCESS_KMS_MASTER_KEY="$(openssl rand -base64 32)" \
  --from-literal=IAM_CORE_CLIENT_SECRET='...' \
  --from-literal=PAM_SSH_HOST_KEY="$(cat ssh_host_key)"

# 2. Install with the production example override.
helm install sa deploy/helm/shieldnet-access \
  -n shieldnet-access \
  -f deploy/helm/shieldnet-access/examples/production.values.yaml \
  --set image.tag=0.1.0
```

The [`examples/production.values.yaml`](helm/shieldnet-access/examples/production.values.yaml)
override turns on autoscaling, ingress, a ServiceMonitor, and PodDisruption
Budgets, and sets the 5,000-tenant replica counts (`ztna-api`=6,
`connector-worker`=3, `workflow-engine`=2, `pam-gateway`=2).

### Quick try (chart-managed secret, not for production)

```bash
helm install sa deploy/helm/shieldnet-access -n shieldnet-access --create-namespace \
  --set secrets.databaseUrl='postgres://user:pass@db:5432/shieldnet_access?sslmode=require' \
  --set secrets.kmsMasterKey="$(openssl rand -base64 32)"
```

## External vs. bundled Postgres

- **External (default, production):** supply `ACCESS_DATABASE_URL` via
  `secrets.existingSecret` or `secrets.databaseUrl`. Keep `postgres.enabled=false`.
- **Bundled dev Postgres (local/dev only):** `--set postgres.enabled=true`. The
  chart deploys a single-replica Postgres `StatefulSet` and auto-derives
  `ACCESS_DATABASE_URL` to point at it. **Not for production** — single replica,
  in-cluster credentials, no backups or HA.

## Scaling

Replica counts are per-component (`ztnaApi.replicaCount`,
`connectorWorker.replicaCount`, `workflowEngine.replicaCount`,
`pamGateway.replicaCount`) and `ztnaApi.autoscaling` provides an HPA.

> **The per-tenant rate limiter is in-memory and therefore per-replica.** With
> `N` `ztna-api` replicas a tenant's effective ceiling is `N × config.rateLimit.rps`.
> Account for `replicaCount` **and** `autoscaling.maxReplicas` when setting it.

Each process owns its own Postgres pool; size Postgres `max_connections` against
the fleet peak `Σ replicas_p × (dbMaxOpenConns + dbPgxMaxConns_p)`. See
[`SCALE_SIZING.md`](SCALE_SIZING.md) for the worked budgets.

## Plain manifests (no Helm)

[`k8s/`](k8s) mirrors the chart's default render (same images, ports, env,
probes, securityContext). Apply order is encoded in the filename prefixes:

```bash
# Edit k8s/03-secret.example.yaml with real values first (or apply your own
# Secret named shieldnet-access-secrets), then:
kubectl apply -f deploy/k8s/
```

## Security posture

- Runs as the non-root `shieldnet` user (uid 10001), `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, all capabilities dropped, `RuntimeDefault`
  seccomp. Components that write (`pam-gateway`'s local replay store) get an
  explicit writable `emptyDir` instead of a writable root fs.
- The ServiceAccount does not mount its API token (the control plane never calls
  the Kubernetes API).
- Secrets are referenced, never written into a ConfigMap, and the chart renders
  no Secret at all when `secrets.existingSecret` is set.

## Local validation gates

These run without a live cluster (used in development of these manifests):

```bash
# Helm chart
helm lint deploy/helm/shieldnet-access
helm template sa deploy/helm/shieldnet-access                                   # default values
helm template sa deploy/helm/shieldnet-access \
  -f deploy/helm/shieldnet-access/examples/production.values.yaml               # production override

# Schema validation of the rendered output and the plain manifests
helm template sa deploy/helm/shieldnet-access | kubeconform -strict -summary -schema-location default
kubeconform -strict -summary -schema-location default deploy/k8s/

# With a live cluster you can instead use:
kubectl apply --dry-run=client -f deploy/k8s/
```
