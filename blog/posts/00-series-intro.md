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
"who can reach what, why, since when, and who signed off." It is built from five
layers that every scenario in this series walks through:

1. **A connector fabric.** 200+ providers (Okta, Salesforce, GitHub, Stripe,
   Azure, GCP, Box, Slack, Datadog, …) plus a first-class **manual** connector
   for offline-fulfilled targets (a core-banking console, an EHR role, a POS
   system). The manual connector provisions and revokes locally, so the access
   lifecycle works even for systems with no API.
2. **Policy packs.** Curated bundles of access-policy templates keyed by
   jurisdiction and compliance framework. Applying a pack materialises **draft**
   policies — it never enforces anything on its own.
3. **The policy lifecycle.** Every draft must be **simulated** (a real dry-run
   impact analysis) and then **promoted** before it takes effect. Promotion is
   the strongest gate in the API: RBAC permission + session MFA + a **fresh
   step-up TOTP** code.
4. **The access lifecycle.** Request → approve → provision → review → certify →
   deprovision, with SCIM-driven joiner/mover/leaver automation and a **leaver
   kill switch** that sweeps every connector supporting session revocation or
   SCIM deprovisioning.
5. **A tamper-evident evidence chain.** Every consequential action appends a
   hash-linked evidence record. You can verify the chain and **export a
   framework-mapped evidence pack** (a ZIP with a manifest carrying the content
   digest and chain-verification status) for an auditor.

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
5. **The critique is honest.** Each post ends with "where we fall short." A
   concrete example you'll see in Post 2: in this self-contained demo the leaver
   kill switch genuinely *fails* on the live SaaS connectors because they carry
   placeholder credentials and there is no real upstream to reach — so it
   reports partial failure. We show that real report rather than hiding it; the
   switch still revokes grants and disables the identity locally and records the
   full layered result.

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
| **Dmitri** | IT admin | One console, safe defaults, JML automation |
| **Sofia** | Security engineer | Step-up MFA, orphan detection, fast leaver deprovisioning |
| **Marcus** | CISO / buyer | Tenant isolation, blast radius, board-ready posture |
| **Aisha** | External auditor | Tamper-evident chain, verifiable export, control-to-evidence mapping |

## The data points

- **200+ connectors** in the catalogue, including the first-class manual
  (offline-target) connector.
- **18 compliance packs** spanning **15+ jurisdictions** (SG, US, DE, VN, AE, AU,
  EU/GDPR, …) and the major frameworks (PCI-DSS v4, HIPAA, SOC 2, ISO 27001,
  GDPR, BSI C5, Essential Eight, PDPA/PDPL/PDPD).
- **5 RBAC roles** — owner, admin, security_admin, operator, auditor — seeded
  into every workspace.
- **12 UI locales**, exercised across the cast (en, zh-Hans, de, ar, vi, ja in
  the screenshot sets).
- **Step-up MFA** (RFC 6238 TOTP, 30s period, anti-replay) on the two
  highest-risk actions: policy promotion and evidence-pack export.

> Exact server-side counts for this seed (members, connectors, policies, active
> policies, access requests, grants, review items, campaign items, orphan
> accounts, evidence records) are in
> [`../artifacts/seed-summary.json`](../artifacts/seed-summary.json). The posts
> cite those numbers directly; they are not estimates.

## How to reproduce everything

See [`README.md`](README.md) for the exact commands (`make blog-seed`,
`make blog-capture`, `make blog-test`) and the environment the harnesses need.
The next post starts in Singapore.
