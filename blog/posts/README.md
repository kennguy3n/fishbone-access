# fishbone-access — the evidence-based access-governance series

An evidence-based engineering series in two parts. **Posts 0–7 (the showcase)**
walk the real product end-to-end across six jurisdictions, with live console
screenshots, verbatim API payloads, on-VM benchmarks, and a tamper-evident
evidence chain you can export and verify. **Posts 8–13 (how to build this)** are
a build-along for engineers *and* product people: the architecture, the data
model, and the wired build steps per subsystem — each anchored to a
business-level decision (why we chose X over Y, and where we deliberately diverge
from the incumbents) seen through the lens of running SaaS security for up to
5,000 resource-light SME tenants. Every figure traces to an evidence source;
every showcase post ends with an honest "where we fall short."

The series covers the full access surface, not just compliance reporting:
**SaaS + internal-system** access through one connector fabric, **PAM** to cloud
VMs (SSH) and managed databases (PostgreSQL/MySQL) via a just-in-time **lease**
lifecycle — reachable through an **outbound connector agent** (zero inbound
exposure) and **clientless from the browser**, with **automatic + dynamic
credential rotation** — **plus a searchable, browser-replayable, chain-anchored
privileged session** (`pam_sessions = 1`; the demo upstream is a bastion, not a
live box), **JML**
(joiner/mover/leaver) with a layered leaver kill switch, **time-boxed contractor
access**, employee-initiated **access requests with AI-assisted risk scoring**
(real agent verdicts, fail-safe degraded default only when the agent is offline),
**separation-of-duties** checks both pre-commit (catastrophic simulation) and as a
**standing anomaly** (`sod_anomalies = 1`), regulation-keyed **access
certification** with a re-verifiable evidence export, **asset/account
auto-discovery + opt-in governed onboarding**, and **cross-replica HA** for the
agent plane. Each showcase post also carries an honest competitor assessment
(Okta IGA, SailPoint, Saviynt, CyberArk, Delinea, BeyondTrust, Teleport,
StrongDM, Tailscale / Cloudflare ZTNA).

## The posts

| # | Post | Scenario | Jurisdiction | Persona |
| --- | --- | --- | --- | --- |
| 0 | [Series intro + the honesty contract](00-series-intro.md) | — | — | — |
| 1 | [Singapore fintech: PDPA + MAS TRM + PCI-DSS](01-singapore-fintech-pdpa-mas-trm.md) | S1 | 🇸🇬 sg | Priya / Marcus |
| 2 | [US healthcare: HIPAA + CCPA, JML + the leaver kill switch](02-us-healthcare-hipaa-ccpa.md) | S2 | 🇺🇸 us | Sofia / Dmitri |
| 3 | [German retail: BDSG + BSI C5 + PCI-DSS + GDPR](03-germany-retail-bdsg-c5-gdpr.md) | S3 | 🇩🇪 de | Priya / Dmitri |
| 4 | [Vietnam: PDPD Decree 13 — an emerging-market posture from one pack](04-vietnam-logistics-pdpd-decree13.md) | S4 | 🇻🇳 vn | Priya / Marcus |
| 5 | [UAE finance: PDPL + DESC — privileged access / PAM](05-uae-finance-pdpl-desc-pam.md) | S5 | 🇦🇪 ae | Sofia / Marcus |
| 6 | [Australian SaaS: Essential Eight + SOC 2 — certify, export, critique](06-australia-saas-essential-eight-soc2.md) | S6 | 🇦🇺 au | Marcus / Aisha |
| 7 | [Benchmarks on this VM — latency, throughput, honest caveats](07-benchmarks-on-this-vm.md) | — | — | Marcus / Dmitri |

### How to build this (a build-along sub-series)

For readers who want to rebuild a system like this. Technical depth with a
business-decision lens at every fork.

| # | Post | Focus |
| --- | --- | --- |
| 8 | [Architecture overview — the shape of a multi-tenant access plane](08-architecture-overview.md) | Binaries, request path, isolation model, build vs buy |
| 9 | [The data model — tenancy, the hash chain, and the access graph](09-data-model.md) | Tables, RLS, the evidence chain formula, per-workspace keys |
| 10 | [Building the connector fabric](10-building-the-connector-fabric.md) | The `AccessConnector` interface, sealed secrets, optional capabilities |
| 11 | [The PAM workflow engine — request to recorded replay](11-pam-workflow-engine.md) | Lease lifecycle, the gateway, rotation, recording + chain |
| 12 | [Discovery and governed onboarding](12-discovery-and-onboarding.md) | Three discovery sources, reconcile, opt-in auto-onboard |
| 13 | [Cross-replica HA for the agent plane](13-cross-replica-ha.md) | Session directory, epoch-CAS ownership, the mTLS forward plane |

Scenario definitions and the evidence map live in
[`../scenarios/00-scenario-catalog.md`](../scenarios/00-scenario-catalog.md).

## Evidence sources (all in-repo)

- **Payloads:** [`../artifacts/payloads/`](../artifacts/payloads/) — verbatim
  control-plane responses captured by [`../harness/capture`](../harness/capture/main.go),
  prefixed `s{n}-{slug}-` per scenario, plus the global catalogue/pack captures
  and two evidence-pack exports (PCI-DSS for S1, SOC 2 for S6) with their
  extracted `manifest.json`. Each scenario includes `-pam-targets`,
  `-pam-leases`, `-pam-sessions`, `-contractor-grants`, `-sod-rules`,
  `-sod-simulation`, `-sod-anomalies`, and `-request-risk` (the AI-risk verdict
  on an access request).
- **Seed summary:** [`../artifacts/seed-summary.json`](../artifacts/seed-summary.json)
  — server-side counts per workspace (ground truth), written by
  [`../harness/seed`](../harness/seed/main.go).
- **Connector / compliance / handler test matrices:**
  `../artifacts/connector-test-matrix.txt`,
  `../artifacts/compliance-test-results.txt`,
  `../artifacts/handler-test-results.txt` — produced by `make blog-test`.
- **Benchmarks:** [`../artifacts/benchmark-results.json`](../artifacts/benchmark-results.json)
  — API latency percentiles + throughput plus the `system` block describing the
  VM, produced by [`../harness/bench`](../harness/bench/main.go) (`make blog-bench`).
- **Screenshots:** `../artifacts/screenshots/` — live console captures taken
  after seeding, including the multi-locale set (en, zh-Hans, de, ar, vi) over
  the same seeded data, produced by the Playwright harness
  [`../harness/screenshots`](../harness/screenshots/shoot.mjs) (`make blog-screenshots`).
  The set includes the new dashboard security-health scorecard, the global help
  drawer, the "What's New" resources card, and the PAM overview page. Identities
  come from `minttokens` and the deep-link IDs are read from the committed capture
  payloads, so the set regenerates against whatever was last seeded — no
  hand-navigation, no hard-coded UUIDs.

## Reproducing the artifacts

The harnesses are Go, consistent with the backend. With Postgres up and the
control plane built, export the dev-auth secret + the credential DEK the seed
uses to enrol the owner's step-up TOTP and seal connector secrets:

```bash
# 0. Environment (dev / non-production only).
export AUTH_JWT_SECRET=...            # the dev HMAC secret the control plane verifies
export ACCESS_CREDENTIAL_DEK=...      # 32-byte base64 DEK; seals TOTP + connector secrets
export ACCESS_DATABASE_URL=postgres://...

# 1. Start the control plane (Go) on :8080 and the console (React) on :5173.
go run ./cmd/ztna-api

# 2. Seed 6 workspaces with the full lifecycle (idempotent — rerun-safe).
make blog-seed
#   equivalently: (cd blog/harness/seed && go run . -base http://localhost:8080 -out ../../artifacts)

# 3. Capture API payloads (GET set + the step-up-gated export POSTs).
make blog-capture
#   equivalently: (cd blog/harness/capture && go run . -base http://localhost:8080 \
#                    -out ../../artifacts/payloads -summary ../../artifacts/seed-summary.json)

# 4. Take screenshots from the live console at localhost:5173 (needs `npm run dev`
#    in ui/). Drives headless Chromium across S1–S6 and every locale, including
#    the interactive policy-conflict + step-up-MFA flow. First run installs
#    Playwright + Chromium automatically.
make blog-screenshots
#   equivalently: go run ./blog/harness/minttokens > tokens.tsv && \
#     BLOG_TOKENS=tokens.tsv node blog/harness/screenshots/shoot.mjs

# 5. Run the connector / compliance / handler test matrices.
make blog-test

# 6. Benchmark the live API on this VM (latency/throughput + system info).
make blog-bench
#   equivalently: (cd blog/harness/bench && go run . -base http://localhost:8080 \
#                    -out ../../artifacts/benchmark-results.json)
```

`make blog-all` runs seed → capture → bench → test in order. (`blog-screenshots`
is kept separate because it additionally needs the UI dev server running.)

The seed and capture harnesses are deterministic against the same seeded data: a
re-run reproduces the same payload files (modulo live timestamps and the export
ZIP's embedded generation time). Screenshots are regenerated the same way — the
[`screenshots`](../harness/screenshots/shoot.mjs) harness drives the live console
headlessly after the seed step, deriving identities and deep-link IDs from
`minttokens` and the committed payloads rather than any hand-navigation.

> **First-run timing.** Promoting a policy and exporting an evidence pack are
> step-up-MFA-gated: each consumes a fresh 6-digit TOTP code, and the server
> enforces anti-replay over a 30-second window. The seed therefore paces
> promotions to the rate the security model genuinely allows (~one new code per
> 30s once a window's three valid codes are spent). A first full seed of all six
> workspaces takes a while for this reason; idempotent re-runs skip
> already-active policies and are fast. This pacing drives the *real*
> replay-protected verifier rather than weakening it.

## The honesty contract (recap)

1. **Payloads are verbatim captures**, never hand-authored — re-running the
   capture reproduces them.
2. **State is driven through the real API** (same validation / RBAC / step-up /
   audit path a console user hits); the only direct DB writes are the iam-core
   identity/tenant bootstrap.
3. **Counts are server-side truth** read back after seeding; the seed is
   idempotent.
4. **Screenshots are of real, seeded pages**; multi-locale shots are the same
   data in another language.
5. **The critique is honest** — every post names where the system falls short
   (e.g. the leaver kill switch's honest partial-failure against unreachable
   live SaaS in the self-contained demo).
