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

Three Go binaries share one image:

| Binary | Role |
| --- | --- |
| `cmd/ztna-api` | HTTP API: workspaces, connectors, access requests, policies. iam-core bearer-token auth + tenant resolution. |
| `cmd/access-connector-worker` | Background queue worker: identity sync, access provisioning/revocation. |
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
# Run the full single-server stack (Postgres + Redis + 3 services).
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
| `IAM_CORE_ISSUER` | iam-core base URL (derives JWKS + discovery). Unset → authenticated API returns 503. |
| `IAM_CORE_CLIENT_ID` / `IAM_CORE_CLIENT_SECRET` | Confidential OAuth2 client for SSO + management. |
| `IAM_CORE_AUDIENCE` | Expected `aud` claim on access tokens. |

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
PAM implementation (1D), the AI agent and workflow engine (1E), and the client
SDKs and deployment tooling (1F).
