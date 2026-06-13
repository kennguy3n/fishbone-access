# Access governance you can actually audit — a series intro

This is the opening post of an evidence-based engineering series about
**fishbone-access**, a multi-tenant access-governance control plane built for
SMEs. The premise of the series is simple and a little unusual: **nothing here
is hand-drawn.** Every screenshot is a real page over real seeded data, every
API payload is a verbatim capture from a running control plane, and every
compliance artifact is a real export you can re-verify. Where the system falls
short, the post says so.

## What fishbone-access is

Most SMEs don't fail audits because they lack controls — they fail because they
can't *prove* the controls ran. fishbone-access is the system of record for
"who can reach what, why, since when, and who signed off." It is built from
layers that every scenario in this series walks through — and the access layer
goes well beyond simple SaaS grants:

1. **A connector fabric.** 200+ providers (Okta, Salesforce, GitHub, Stripe,
   Azure, GCP, Box, Slack, Datadog, …) plus a first-class **manual** connector
   for offline-fulfilled targets (a core-banking console, an EHR role, a POS
   system). The manual connector provisions and revokes locally, so the access
   lifecycle works even for systems with no API. This is how access to **SaaS
   apps and internal systems** is onboarded and torn down through one fabric.
2. **Policy packs.** Curated bundles of access-policy templates keyed by
   jurisdiction and compliance framework. Applying a pack materialises **draft**
   policies — it never enforces anything on its own.
3. **The policy lifecycle.** Every draft must be **simulated** (a real dry-run
   impact analysis) and then **promoted** before it takes effect. Promotion is
   the strongest gate in the API: RBAC permission + session MFA + a **fresh
   step-up TOTP** code. The same simulation runs a **separation-of-duties (SoD)
   toxic-combination check** that flags *catastrophic* grants before they land.
4. **The access lifecycle.** Request → approve → provision → review → certify →
   deprovision. Every policy decision is a **route**: a request resolves to a
   `grant` or a `deny`, and **deny always wins on conflict** — that is how
   "allow this, block that" is expressed and how toxic combinations are caught.
   Employee-initiated requests are then **AI-risk-scored** before a human sees
   them, and the verdict carries an explicit **approval route** —
   `auto_approve_eligible`, `needs_review`, or `high_risk` — so low-risk requests
   can be fast-tracked while risky ones are forced to a human. When the risk
   agent is unreachable the route fails **closed** to `needs_review`; it never
   auto-approves on failure. SCIM-driven **joiner/mover/leaver (JML)** automation
   keeps grants in step with identity and role changes, and a **leaver kill
   switch** sweeps every connector supporting session revocation or SCIM
   deprovisioning.
5. **Privileged access (PAM).** Privileged targets — **cloud VMs over SSH** and
   **managed databases over their native wire protocol** — are registered in a
   vault and reached through a **just-in-time lease**: request → sponsor approval
   (step-up MFA) → short-lived connect-token → automatic expiry. Every step is
   risk-scored and recorded.
6. **Contractor access.** Time-boxed, sponsor-approved grants for external
   parties, with a **mandatory expiry**, a named internal sponsor, and a full
   extend / early-revoke history — a separate lifecycle from employees.
7. **A tamper-evident evidence chain.** Every consequential action across all of
   the above appends a hash-linked evidence record. You can verify the chain —
   a full O(n) recompute of every link, or an **incremental O(Δ) consistency
   verify** that re-checks only the rows added since a trusted anchor, so the
   heaviest endpoint stays cheap as a workspace accretes years of evidence — and
   **export a framework-mapped evidence pack** (a ZIP with a manifest carrying
   the content digest and chain-verification status, plus a `pam-recordings.jsonl`
   line for each recorded privileged session in the pack) for an auditor — the
   **access-certification** artifact regulators ask to see.

## The honesty contract

This series is a critique, not a brochure. Five rules hold for every post:

1. **Payloads are verbatim captures.** Files under
   [`../artifacts/payloads/`](../artifacts/payloads/) are produced by
   [`blog/harness/capture`](../harness/capture/main.go), which GETs a live
   control plane and pretty-prints the response. Re-running it against the same
   seeded data reproduces the same files.
2. **State is driven through the real API.** [`blog/harness/seed`](../harness/seed/main.go)
   builds every workspace by calling the same HTTP endpoints a console user hits
   — through the same validation, RBAC, step-up-MFA, and audit-chain code. The
   *only* direct database writes are the identity/tenant bootstrap that iam-core
   owns in production and that has no self-service API: the workspace row, the
   owner's membership, and the owner's enrolled TOTP secret.
3. **Counts are server-side truth.** [`../artifacts/seed-summary.json`](../artifacts/seed-summary.json)
   reports counts read back via GET after seeding, so the numbers are the true
   present state — not merely what one run created. The seed is idempotent.
4. **Screenshots are of real, seeded pages.** They're taken from the live
   console after seeding. The multi-locale set re-renders the *same* data in
   another language (en, zh-Hans, de, ar, vi, ja) to show i18n coverage, not a
   different dataset.
5. **The critique is honest.** Each post ends with "where we fall short." The
   clearest example you'll see: in Post 2 the leaver kill switch genuinely
   *fails* on the live SaaS connectors because they carry placeholder credentials
   and there is no real upstream to reach — so it reports partial failure; the
   switch still revokes grants and disables the identity locally and records the
   full layered result. The honest boundary is drawn at the *line* the demo can
   reach, not hidden.

### What changed since the first cut of this series

An earlier version of these posts flagged a recurring set of controls as
**uncovered (0 records)** — privileged-session monitoring (SOC 2 **CC6.7** / ISO
**A.8.2** / PCI-DSS **10.2**), the standing separation-of-duties anomaly (**CC7.3**),
the tamper-evident-export evidence kind (**A.8.15**), and AI risk scoring that
ran **degraded** because the agent was offline. Re-reading the code made one thing
clear: **most of those were seed-harness gaps, not product gaps** — the
control→evidence mapping already existed; the old seed simply never emitted the
evidence. This cut closes them with capabilities the product already ships, and
nothing is faked:

- **CC6.7 / A.8.2 / PCI-DSS 10.2** — every workspace now opens a **real recorded
  privileged session**: a JIT lease is redeemed, the operator's commands are
  driven through the same `IORecorder` the live gateway uses, the framed
  transcript is persisted to the replay store, its SHA-256 is **anchored in the
  hash chain**, and it is **retrievable over `GET /pam/sessions/:id/replay`**.
  `pam_sessions = 1` per workspace, and the coverage map flips these controls to
  *covered*. The honest residual: the recorded commands are seeded representative
  I/O against a registered bastion target — the demo has no live SSH daemon — so
  this proves the **recording pipeline and the chained, replayable session
  artifact end-to-end**, not keystrokes captured off a production box.
- **CC7.3** — one dedicated subject is granted **both halves of the workspace's
  toxic-combination rule** as live, approved grants, and the production anomaly
  sweep records the standing violation + disposition. `sod_anomalies = 1`,
  detected against live state — not a what-if.
- **A.8.15 / PCI-DSS 10.2** — the evidence-pack export now runs **before** the
  capture snapshots the chain (it was an ordering bug), so `evidence_exported` is
  in-chain and the tamper-evident-logging control reads covered.
- **AI risk scoring** — the agent is online over A2A mTLS, so risk verdicts now
  show `source: ai_agent`, `degraded: false`, with a real recommendation — not the
  fail-closed `needs_review` safety net.

What this cut adds on top of closing those gaps is the **scale** answer for the
evidence chain itself. The series' own benchmark (Post 7) is blunt that a full
chain-verify is **O(n)** in chain length — the single worst-scaling endpoint at
5,000-tenant SaaS scale, where workspaces accrete evidence for years. So the
same `GET /compliance/chain/verify` route now also takes a trusted anchor
(`?from_seq=&from_hash=`) and runs an **incremental consistency verify** that
re-checks only the suffix appended since that anchor: an interactive dashboard
pays the O(n) cost once to establish a baseline, then O(Δ) on every refresh
thereafter. On this VM that is a **10.15 ms → 3.45 ms p50** drop on a ~100-row
chain (Post 7); the gap widens without bound as the chain grows. The honest
boundary is stated wherever it appears: the incremental call is a *consistency*
proof of the suffix, **not** a fresh *integrity* proof of the whole chain — the
periodic full sweep remains the root of trust.

What stays honest (real hard limits a self-contained demo cannot close): killing
a *real* Okta/Box session (no upstream credentials — Post 2); logging every read
performed **directly inside** the downstream app rather than through our gateway
(PCI-DSS 10.2 / HIPAA §164.312(b) for app-native reads still needs the app's audit
log or a SIEM); executing a CCPA *deletion* downstream; deep per-provider
connector provisioning; and the methodology line that **SoD here is declared
rules, not graph-mined discovery**, and **orphan handling is detection, not
behavioural analytics**. Every post draws that line on screen.

### Q0 — Does our ZTNA "darken the whole network"? Which ZTNA attributes do we adhere to?

Short answer: **no — fishbone-access is an identity-aware access *control plane and
target broker*, not an L3 data-plane that makes an entire subnet invisible.** It
adheres to the NIST SP 800-207 tenets that live in the *authorization decision*,
and it explicitly delegates the network-darkening tenets to the data-plane gateway
(the SNG / visible-fishbone side of the house).

> **A terminology note before the table.** "ZTNA" (Zero Trust Network Access) is a
> Gartner *market category*; the normative standard is NIST SP 800-207, **Zero Trust
> Architecture (ZTA)**, whose 7 tenets we cite below. In 800-207 terms, fishbone-access
> is the **Policy Decision Point (PDP)** — the policy engine that resolves
> `grant`/`deny` — and the **Policy Enforcement Point (PEP) at the broker** (the
> connect-token redemption that opens or refuses a session). The *in-path* PEP that
> drops packets for an unauthorized identity (the "dark network" property) is the
> data-plane gateway, not this control plane. So we adhere to the **decision-side**
> tenets and delegate the **packet-side** ones. We use "ZTNA" loosely in prose but
> map every claim to a numbered 800-207 tenet so an auditor can trace it.

| ZTNA tenet (NIST 800-207 tenet #) | fishbone-access | Where it lives |
| --- | --- | --- |
| **No standing access / per-session grant** (Tenet 3 — *per-session access*) | **Enforced.** JIT leases and connect-tokens with mandatory expiry; nothing is durable. | access + PAM lifecycle |
| **Identity-aware, per-request decision** (Tenets 4 & 6 — *dynamic policy*; *auth strictly enforced before access*) | **Enforced.** Every request resolves through the PDP to a `grant`/`deny` route; **deny wins on conflict**. | policy engine (PDP) |
| **Least privilege, dynamic** (Tenet 4 — *dynamic policy*) | **Enforced.** Per-target, per-role grants + command-level gating on privileged sessions. | PAM + policy |
| **Continuous / step-up re-evaluation** (Tenets 5 & 7 — *measure posture*; *collect state to improve decisions*) | **Enforced.** Fresh step-up TOTP on the highest-risk actions; AI risk re-scores each request. | step-up MFA + risk |
| **Per-resource segmentation** (Tenets 1 & 3 — *resources*; *per-session, per-resource*) | **Enforced at the broker (PEP).** One-shot connect-token scopes to a single target; no lateral catalogue. | PAM broker (PEP) |
| **Resource invisible until authorized (L3 "dark" network)** (Tenets 2 & 6 — *all communication secured*; *enforced before access*, at the in-path PEP) | **Delegated.** We don't darken a subnet or sink unauthenticated packets; that is the in-path gateway's job. | pam-gateway / SNG |
| **In-path session inspection / kill** (Tenets 5 & 7 — *monitor and measure live sessions*) | **Partial.** We record a brokered session and can revoke the lease; killing a *live third-party* session needs real upstream creds. | gateway + connectors |

So the precise framing the series uses: fishbone-access makes resources
**default-deny and unreachable-without-an-authorized-lease at the control plane**,
and brokers a recorded, least-privilege, time-boxed session to a single target —
but the "the port doesn't even answer for an unauthorized identity" L3 darkening is
a property of the data-plane gateway (the in-path PEP), not of this control plane.

## The cast — six workspaces

The series follows six SME tenants, each a different jurisdiction and industry,
seeded into one control plane to demonstrate per-tenant isolation:

| # | Workspace | Region | Industry | Packs | Headline locale |
| --- | --- | --- | --- | --- | --- |
| 1 | Acme Payments | 🇸🇬 sg | finance | `sg-pdpa-mas-trm`, `pci-dss-v4` | en |
| 2 | Globex Health | 🇺🇸 us | healthcare | `hipaa-security-rule`, `us-ccpa-cpra` | en |
| 3 | Initech Retail | 🇩🇪 de | retail | `de-bdsg-c5`, `gdpr-personal-data`, `pci-dss-v4` | de |
| 4 | Umbrella Logistics | 🇻🇳 vn | logistics | `vn-pdpd-decree13` | vi |
| 5 | Northwind Finance | 🇦🇪 ae | finance | `ae-pdpl-desc`, `iso27001-annexa` | ar (RTL) |
| 6 | Contoso SaaS | 🇦🇺 au | saas | `au-privacy-e8`, `soc2-logical-access` | en |

Tenant isolation is enforced at the row level on every table; the seed proves it
by minting a *separate* per-workspace identity and never crossing tenant
boundaries.

## The personas

| Persona | Role | Cares about |
| --- | --- | --- |
| **Priya** | Compliance officer | Framework coverage, defensible evidence, on-time recertification |
| **Dmitri** | IT admin | One console, safe defaults, JML automation, contractor onboarding |
| **Sofia** | Security engineer | Step-up MFA, JIT privileged leases, orphan detection, fast leaver deprovisioning |
| **Marcus** | CISO / buyer | Tenant isolation, blast radius, SoD toxic-combinations, board-ready posture |
| **Aisha** | External auditor | Tamper-evident chain, verifiable export, control-to-evidence mapping |

## The data points

- **200+ connectors** in the catalogue, including the first-class manual
  (offline-target) connector.
- **19 compliance packs** spanning **15+ jurisdictions** (SG, US, DE, VN, AE, AU,
  EU/GDPR, …) and the major frameworks (PCI-DSS v4, HIPAA, SOC 2, ISO 27001,
  GDPR, BSI C5, Essential Eight, PDPA/PDPL/PDPD).
- **5 RBAC roles** — owner, admin, security_admin, operator, auditor — seeded
  into every workspace.
- **PAM** to cloud VMs (SSH) and managed databases (PostgreSQL / MySQL) via the
  vault + just-in-time lease lifecycle, with **10 supported protocols** (ssh,
  postgres, mysql, mssql, mongodb, redis, k8s-exec, rdp, vnc, http) on the
  register screen.
- **Time-boxed contractor access** — sponsor-approved external grants with a
  mandatory expiry and an extend / early-revoke history.
- **AI-assisted risk scoring** on every access request and PAM lease, routing
  each to `auto_approve_eligible` / `needs_review` / `high_risk`. In this seed the
  agent is **online** (A2A mTLS), so verdicts are real (`source: ai_agent`,
  `degraded: false`); the fail-closed `needs_review` default still applies when the
  agent is unavailable (shown verbatim — never an auto-approve on failure).
- **On-VM benchmarks** of the live API (latency percentiles + throughput),
  captured by [`blog/harness/bench`](../harness/bench/main.go) on this dev box
  and written to [`../artifacts/benchmark-results.json`](../artifacts/benchmark-results.json).
  See [Post 7](07-benchmarks-on-this-vm.md) for the methodology and honest
  caveats.
- **Separation-of-duties — pre-commit *and* standing.** The toxic-combination
  engine marks a grant `catastrophic` *before* it is committed, and a standing
  anomaly sweep records `sod_violation` for any subject already holding both halves
  of a rule (`sod_anomalies = 1` per workspace this seed). Declared rules, not
  graph-mined discovery — the honest line every country post repeats.
- **12 UI locales**, exercised across the cast (en, zh-Hans, de, ar, vi, ja in
  the screenshot sets).
- **Recorded privileged sessions** — every workspace opens one real JIT-leased,
  gateway-recorded session (`pam_sessions = 1`); the framed transcript is
  retrievable over `GET /pam/sessions/:id/replay` and its digest is chained.
- **Step-up MFA** (RFC 6238 TOTP, 30s period, anti-replay) on the highest-risk
  actions: policy promotion, evidence-pack export, and privileged-lease approval.

> Exact server-side counts for this seed (members, connectors, policies, active
> policies, access requests, grants, review items, campaign items, orphan
> accounts, evidence records) are in
> [`../artifacts/seed-summary.json`](../artifacts/seed-summary.json). The posts
> cite those numbers directly; they are not estimates.

## How to reproduce everything

See [`README.md`](README.md) for the exact commands (`make blog-seed`,
`make blog-capture`, `make blog-bench`, `make blog-test`) and the environment the
harnesses need. The next post starts in Singapore; the series closes in
[Post 7](07-benchmarks-on-this-vm.md) with the numbers this VM actually turned
in.
