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
   the above appends a hash-linked evidence record. You can verify the chain and
   **export a framework-mapped evidence pack** (a ZIP with a manifest carrying
   the content digest and chain-verification status, plus a `pam-recordings.jsonl`
   slot the pack now ships even when it is empty) for an auditor — the
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
5. **The critique is honest.** Each post ends with "where we fall short." Two
   concrete examples you'll see: in Post 2 the leaver kill switch genuinely
   *fails* on the live SaaS connectors because they carry placeholder credentials
   and there is no real upstream to reach — so it reports partial failure; the
   switch still revokes grants and disables the identity locally and records the
   full layered result. And across **every** workspace the PAM **lease lifecycle**
   is exercised and recorded, but `pam_sessions = 0` and the control
   "privileged access *monitored*" (SOC 2 CC6.7 / ISO A.8.2) stays at **0
   records** — because recording the *session itself* needs the gateway in the
   connection path with a reachable upstream, which the self-contained demo does
   not have. We govern the privileged *lease*; we do not yet record the privileged
   *session*. The coverage map says so on screen.

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
  each to `auto_approve_eligible` / `needs_review` / `high_risk`, with a
  fail-closed `needs_review` default when the AI agent is unavailable (honest,
  and shown verbatim — never an auto-approve on failure).
- **On-VM benchmarks** of the live API (latency percentiles + throughput),
  captured by [`blog/harness/bench`](../harness/bench/main.go) on this dev box
  and written to [`../artifacts/benchmark-results.json`](../artifacts/benchmark-results.json).
  See [Post 7](07-benchmarks-on-this-vm.md) for the methodology and honest
  caveats.
- **Separation-of-duties simulation** — a toxic-combination engine that marks a
  grant `catastrophic` *before* it is committed.
- **12 UI locales**, exercised across the cast (en, zh-Hans, de, ar, vi, ja in
  the screenshot sets).
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
