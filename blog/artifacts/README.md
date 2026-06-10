# Blog artifacts — provenance & integrity

Every figure in the blog series traces back to one of these files. This README
records exactly how each was produced and what it does (and does not) prove.

## `seed-summary.json` — server-side ground truth (REAL)

- **Produced by:** [`blog/harness/seed`](../harness/seed/main.go) — `make blog-seed`.
- **How:** the harness bootstraps each workspace's identity (the iam-core
  workspace row, owner membership, and owner TOTP secret — the only direct DB
  writes), then drives the *entire* lifecycle over the real HTTP API: RBAC
  members, connectors, pack apply, policy simulate + promote (step-up MFA),
  access requests + approve + provision, an access-review campaign with
  decisions, a certification campaign with decisions + close, an orphan scan, and
  SCIM joiner/mover/leaver. It then **reads counts back via GET** and writes them
  here.
- **What it proves:** the present, server-confirmed state of each of the six
  workspaces — every row flowed through validation, RBAC, step-up MFA, and the
  audit/evidence chain. Counts are authoritative because they're read back, not
  tallied from what one run created.
- **What it does NOT prove:** it is demo data on a self-contained stack. The
  connectors carry placeholder credentials, so anything that needs a live
  upstream (e.g. confirming SaaS deprovisioning) is exercised but cannot succeed
  against a real system — see the leaver note below.
- **Idempotent:** a re-run creates nothing new; existing resources are detected
  (and a 409 is treated as "already exists"), so the summary is stable.

## `payloads/*.json` — verbatim API captures (REAL)

- **Produced by:** [`blog/harness/capture`](../harness/capture/main.go) — `make blog-capture`.
- **How:** mints the same per-workspace token the seed used, GETs a fixed set of
  scenario-relevant endpoints, and pretty-prints each response. Files are
  prefixed `s{n}-{slug}-` per scenario; tenant-agnostic captures are prefixed
  `global-`.
- **Per workspace:** packs (region-filtered), policies, access-requests,
  connectors, catalogue facets, orphan-accounts, compliance evidence, coverage,
  chain verify, campaigns, the campaign report, the access-review report + items,
  and connector SSO status.
- **Global (once):** connector providers, the full pack catalog, and the pack
  catalog filtered by tier (1/2/3).
- **What it proves:** these are exactly the bytes the API returns for the seeded
  data. No payload is edited by hand; re-running the capture reproduces them.
- **What it does NOT prove:** an empty collection in a payload is an honest empty
  state, not a rendering trick — the blog captures it as-is rather than
  hand-filling it.

## `payloads/*-evidence-pack.zip` + `*-evidence-pack-manifest.json` — framework export (REAL)

- **Produced by:** [`blog/harness/capture`](../harness/capture/main.go) via
  `POST /api/v1/compliance/export`, for two workspaces: **Acme Payments (SG)**
  under **PCI-DSS** and **Contoso SaaS (AU)** under **SOC 2**.
- **How:** the export is the single most-privileged route — it requires the
  `compliance.export` RBAC permission **and** a fresh step-up TOTP assertion. The
  capture harness supplies a real, currently-valid, never-reused code. The server
  records the export in the tamper-evident chain *before* delivering the bytes,
  anchoring exactly which content was exported. The harness saves the ZIP
  verbatim and extracts `manifest.json` from it.
- **What it proves:** a real, framework-mapped evidence pack can be produced and
  re-verified; `manifest.json` carries the content SHA-256, evidence total, and
  chain-verification status.
- **What it does NOT prove:** coverage percentages reflect the *seeded* evidence,
  not a full production history. The manifest reports what the chain actually
  contains.

## `connector-test-matrix.txt` / `compliance-test-results.txt` / `handler-test-results.txt` — test matrices (REAL)

- **Produced by:** `make blog-test`, which runs
  `go test ./internal/services/access/connectors/...`,
  `./internal/services/compliance/...`, and `./internal/handlers/...` with `-v`
  and tees the output here.
- **What it proves:** the connector validators, the compliance engine, and the
  HTTP handlers pass their unit/integration suites at the captured commit.
- **What it does NOT prove:** unit/integration coverage is not a security audit;
  it shows no regressions against the cases the suites encode.

## `screenshots/` — live console captures (REAL)

- **How:** taken from the live console at `localhost:5173` **after** seeding, so
  every screen shows real seeded data. The multi-locale set re-renders the same
  data in another language (en, zh-Hans, de, ar, vi, ja) to demonstrate i18n
  coverage — including RTL for `ar` (Northwind Finance).
- **What it does NOT prove:** screenshots are of the seeded demo dataset, not a
  customer's production tenant.

## Honesty contract (applies to the whole series)

1. **Verbatim** = the exact API bytes (payloads, export manifests). **Server
   truth** = counts read back after seeding (`seed-summary.json`).
2. State is driven through the real API; the only direct DB writes are the
   iam-core identity/tenant bootstrap.
3. Screenshots are of real, seeded pages; multi-locale shots are the same data in
   another language.
4. Each post ends with an honest "where we fall short." The clearest example: the
   leaver kill switch reports **partial failure** on unreachable live SaaS
   connectors in this self-contained demo (placeholder credentials, no real
   upstream). The switch still revokes grants and disables the identity locally
   and records the full layered report — and the blog shows that report rather
   than masking it.
