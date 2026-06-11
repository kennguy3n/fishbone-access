# fishbone-access — Scenario Catalog

> The contract for the blog series. It defines the six business scenarios the
> series is built around, the personas behind each, the product capabilities
> each exercises, the UI surfaces involved, and — critically — **where each
> post's evidence comes from** and **what it does vs. does not prove**.
>
> Every figure, screenshot, and payload in a published post must trace back to
> an evidence source named here. Nothing is hand-authored.

---

## What fishbone-access is

fishbone-access is a multi-tenant **access-governance control plane** for SMEs:
connector fabric (200+ providers) → policy packs by jurisdiction/framework →
the access lifecycle (request → approve → provision → review → certify →
deprovision) → a tamper-evident evidence chain you can export as a
framework-mapped compliance pack. Five RBAC roles, step-up MFA on the
highest-risk actions, and row-level tenant isolation across every table.

---

## Evidence-integrity rules (apply to every post)

1. **Payloads are verbatim captures.** Everything under
   [`../artifacts/payloads/`](../artifacts/payloads/) is written by
   [`blog/harness/capture`](../harness/capture/main.go) GET-ing a live control
   plane and pretty-printing the response. No payload is edited by hand. Re-running
   the capture against the same seeded data reproduces the same files (export
   ZIP timestamps aside).
2. **State is driven through the real API.** [`blog/harness/seed`](../harness/seed/main.go)
   creates every workspace's data by calling the same HTTP endpoints a console
   user hits — through the same validation, RBAC, step-up-MFA and audit-chain
   path. The only direct DB writes are the identity/tenant bootstrap iam-core
   owns in production and which has no self-service API (the workspace row, the
   owner's membership, and the owner's enrolled TOTP secret).
3. **Counts are server-side truth.** [`../artifacts/seed-summary.json`](../artifacts/seed-summary.json)
   reports counts read back via GET after seeding — the true present state, not
   merely what one run created. The seed is idempotent: a re-run creates nothing
   new.
4. **Screenshots are of real, seeded pages.** Captures are taken from the live
   console after seeding, showing real data. Multi-locale screenshots switch the
   UI locale (en, zh-Hans, de, ar, vi, ja) over the *same* seeded data to show
   i18n coverage, not a different dataset.
5. **The critique is honest.** Each post ends with a "where we fall short"
   section. Where the self-contained demo cannot show something (e.g. live SaaS
   deprovisioning against a real upstream), the post says so — see the leaver
   kill-switch note in §S2.

---

## Personas

| Persona | Who | What they care about |
| --- | --- | --- |
| **Priya** — Compliance officer | Owns the audit calendar at a regulated SME | Framework coverage, defensible evidence, recertification on time |
| **Dmitri** — IT admin | One-person IT running the connector fabric | One console, safe defaults, JML automation, no bespoke scripts |
| **Sofia** — Security engineer | Owns least-privilege and the kill switch | Step-up MFA, orphan detection, fast leaver deprovisioning |
| **Marcus** — CISO / buyer | Signs off on the control posture | Tenant isolation, blast radius, board-ready compliance posture |
| **Aisha** — External auditor | Samples evidence at certification time | Tamper-evident chain, verifiable export, control-to-evidence mapping |

---

## The scenarios

Six scenarios, one per workspace/jurisdiction. Each names the business problem,
the packs applied, the connector fabric, the lifecycle actions taken, the
compliance artifact produced, and the evidence source.

### S1 — Singapore fintech: PDPA + MAS TRM + PCI-DSS
- **Workspace:** Acme Payments (`sg`, finance). **Personas:** Priya, Marcus.
- **Business problem:** a payments SME under MAS Technology Risk Management must
  prove least-privilege over its core ledger and PCI-DSS scope over its CDE.
- **Packs:** `sg-pdpa-mas-trm`, `pci-dss-v4`.
- **Connectors:** Stripe (payments), Salesforce (CRM), GitHub (engineering),
  manual MAS-TRM privileged-ops target.
- **Lifecycle:** apply packs → simulate + promote each draft policy (step-up MFA)
  → **AI-risk-scored** ledger access request → **PAM targets** (ledger Postgres +
  SSH host) with a **JIT lease** (request→approve under step-up→mint→expire) →
  **SoD simulation** rejecting the ledger-admin↔reconcile toxic combo
  (`catastrophic`) → **contractor grant** (PayTech integrator, time-boxed) →
  PCI CDE audit request → MAS-TRM privileged-access review with a revoke → PCI-DSS
  certification campaign → orphan scan → JML joiner/mover/leaver.
- **Compliance artifact:** **PCI-DSS evidence pack** (ZIP + manifest).
- **Evidence:** `s1-sg-acme-payments-*.json` (incl. `-request-risk`,
  `-pam-targets`, `-pam-leases`, `-pam-sessions`, `-sod-rules`, `-sod-simulation`,
  `-contractor-grants`), `s1-sg-acme-payments-evidence-pack.zip` + `-manifest.json`.

### S2 — US healthcare: HIPAA + CCPA/CPRA (JML + leaver kill switch)
- **Workspace:** Globex Health (`us`, healthcare). **Personas:** Sofia, Dmitri.
- **Business problem:** a digital-health SME must enforce HIPAA minimum-necessary
  on ePHI and fulfil CCPA/CPRA consumer requests, with clean joiner/mover/leaver.
- **Packs:** `hipaa-security-rule`, `us-ccpa-cpra`.
- **Connectors:** Okta (workforce SSO), Box (clinical documents), manual Epic EHR
  clinical-role target.
- **Lifecycle:** clinician + billing onboarding provisioned → PHI-export auditor
  request → HIPAA ePHI access review → certification campaign → orphan scan →
  **JML joiner → mover → leaver kill switch**.
- **Compliance artifact:** access-review report + certification campaign report.
- **Honest note:** the leaver kill switch sweeps *every* connector that supports
  session-revoke / SCIM-deprovision. In this self-contained demo the live SaaS
  connectors carry placeholder credentials, so those layers genuinely fail — the
  switch still revokes grants and disables the identity locally and records the
  full layered report, but reports partial failure because it cannot confirm
  revocation on an unreachable upstream. The post shows that real report rather
  than masking it.
- **Evidence:** `s2-us-globex-health-*.json` (review-report, review-items,
  campaign-report).

### S3 — German retail: BDSG + BSI C5 + PCI-DSS + GDPR (multi-framework fabric)
- **Workspace:** Initech Retail (`de`, retail). **Personas:** Priya, Dmitri.
- **Business problem:** a retailer must satisfy four overlapping frameworks at
  once over one connector fabric without duplicating controls.
- **Packs:** `de-bdsg-c5`, `gdpr-personal-data`, `pci-dss-v4`.
- **Connectors:** GitHub (e-commerce), Datadog (observability), Azure (cloud
  infra), manual SAP retail-POS target.
- **Lifecycle:** richest policy set (three packs) → store-manager + CDE
  maintenance provisioned → GDPR Article 15 export request → BSI C5 + GDPR review
  → ISO 27001 certification campaign → orphan scan → JML.
- **Compliance artifact:** coverage map across frameworks + connector catalogue
  facets.
- **Evidence:** `s3-de-initech-retail-*.json` (coverage, catalogue-facets,
  policies).

### S4 — Vietnam logistics: PDPD Decree 13 (emerging-market compliance)
- **Workspace:** Umbrella Logistics (`vn`, any). **Personas:** Priya, Marcus.
- **Business problem:** an emerging-market logistics SME must stand up a credible
  data-protection posture under Vietnam's PDPD Decree 13 from a single pack.
- **Packs:** `vn-pdpd-decree13`.
- **Connectors:** GitHub (logistics platform), Slack (operations), manual
  warehouse-WMS target.
- **Lifecycle:** dispatcher + inventory provisioned → Decree-13 register review
  request → PDPD access review → certification campaign → orphan scan → JML.
- **Compliance artifact:** the single-pack starting posture (the "day one"
  story) + chain-verify.
- **Evidence:** `s4-vn-umbrella-logistics-*.json` (packs filtered to `vn`,
  chain-verify).

### S5 — UAE finance: PDPL + DESC + ISO 27001 (privileged access / PAM)
- **Workspace:** Northwind Finance (`ae`, finance). **Personas:** Sofia, Marcus.
- **Business problem:** a wealth-management firm under UAE PDPL and Dubai DESC
  must tightly control privileged access to core banking.
- **Packs:** `ae-pdpl-desc`, `iso27001-annexa`.
- **Connectors:** Salesforce (wealth CRM), Okta (workforce SSO), manual Temenos
  T24 core-banking privileged-account target.
- **Lifecycle:** **PAM targets** (Temenos T24 SSH host + Treasury Postgres, 15-min
  lease ceiling, step-up-gated) with two **JIT leases** → **SoD simulation**
  rejecting core-banking-admin↔treasury-settlement (`catastrophic`) → **DESC
  external-auditor contractor grant** → short-TTL privileged-admin + treasury
  grants → PDPL DSR auditor request → DESC privileged-access review with a revoke
  → ISO 27001 Annex A certification → orphan scan → JML. Locale `ar` exercises RTL.
- **Compliance artifact:** privileged-access review + ISO 27001 certification.
  Honest boundary: `A.8.2` "privileged access *monitored*" stays at **0 records** —
  the JIT lease is governed and chained, but the session is not recorded.
- **Evidence:** `s5-ae-northwind-finance-*.json` (review-report, sso-status,
  `-pam-targets`, `-pam-leases`, `-pam-sessions`, `-sod-simulation`,
  `-contractor-grants`).

### S6 — Australian SaaS: Essential Eight + SOC 2 (certify + export + critique)
- **Workspace:** Contoso SaaS (`au`, saas). **Personas:** Marcus, Aisha.
- **Business problem:** a SaaS vendor must pass a SOC 2 Type II audit and meet
  ACSC Essential Eight admin-privilege restriction, then hand an auditor a
  verifiable evidence pack.
- **Packs:** `au-privacy-e8`, `soc2-logical-access`.
- **Connectors:** GitHub (product eng), GCP (production), Slack (engineering),
  manual billing-console target.
- **Lifecycle:** RevOps + time-boxed deploy grants → SOC 2 evidence-sampling
  auditor request → SOC 2 Type II recertification review → **SOC 2 certification
  campaign closed** → **SOC 2 evidence pack exported** (step-up MFA) → orphan
  scan → JML.
- **Compliance artifact:** **SOC 2 evidence pack** (ZIP + manifest) + closed
  campaign report — the competitive-critique post.
- **Evidence:** `s6-au-contoso-saas-*.json`, `s6-au-contoso-saas-evidence-pack.zip`
  + `-manifest.json`.

---

## Coverage check — every major surface is represented

| Capability / surface | Scenario(s) |
| --- | --- |
| Connector fabric (200+ providers) | S1–S6 |
| Manual / offline-target connector | S1–S6 |
| Policy packs by jurisdiction | S1 (sg), S3 (de), S4 (vn), S5 (ae), S6 (au) |
| Policy packs by framework | PCI-DSS (S1, S3), HIPAA (S2), GDPR/BDSG/C5 (S3), ISO 27001 (S5), SOC 2 (S6) |
| Policy lifecycle: apply → simulate → promote | S1–S6 |
| Step-up MFA (promote + export + lease approval) | S1 (promote), S6 (export), S1/S2/S5 (lease) |
| Access requests → approve → provision | S1–S6 |
| Access request **AI risk verdict** (degraded fail-safe) | S1–S6 (`-request-risk`) |
| **PAM targets** (SSH/Postgres/MySQL cloud-VM + DB) | S1, S2, S3, S4, S5, S6 (`-pam-targets`) |
| **PAM JIT lease** lifecycle (request→approve→expire) | S1, S2, S5 highlighted; `-pam-leases` |
| **PAM session recording** (honest 0-record gap) | S1–S6 (`-pam-sessions` = 0) |
| **Contractor access** (time-boxed sponsor grant) | S1–S6 (`-contractor-grants`) |
| **SoD toxic-combo rule + simulation** (`catastrophic`) | S1, S3, S5 highlighted; `-sod-rules` / `-sod-simulation` |
| Access-review campaign + decisions | S1–S6 |
| Certification campaign + decisions + close | S1–S6 (closed in S6) |
| Orphan scan | S1–S6 |
| SCIM joiner / mover / leaver kill switch | S2 (highlighted), S1–S6 |
| Tamper-evident evidence chain + verify | S4 (chain-verify), S1/S6 (export) |
| Framework-mapped evidence-pack export | S1 (PCI-DSS), S6 (SOC 2) |
| Coverage map across frameworks | S3 |
| RBAC: 5 roles | S1–S6 (seeded per workspace) |
| Multi-locale UI (en, de, vi, ar, …) | S3 (de), S4 (vi), S5 (ar) |

---

## Blog series outline

0. **Series intro + the honesty contract** — what fishbone-access is, the cast of
   six workspaces, the personas, and the evidence rules above.
1. **S1 — Singapore fintech** (PDPA + MAS TRM + PCI-DSS): packs → policies →
   AI-risk-scored requests → JIT PAM lease → SoD simulation → contractor access →
   evidence pack.
2. **S2 — US healthcare** (HIPAA + CCPA): certification campaigns, JML lifecycle,
   the leaver kill switch, ePHI PAM lease, access review.
3. **S3 — German retail** (BDSG + C5 + PCI-DSS + GDPR): multi-framework coverage
   over one connector fabric + the SoD toxic-combination check.
4. **S4 — Vietnam** (PDPD Decree 13): standing up an emerging-market posture from
   one pack — with the full access primitives (PAM lease, contractor, SoD).
5. **S5 — UAE finance** (PDPL + DESC): privileged access — the JIT lease now
   exists, the session recording still doesn't; RTL locale.
6. **S6 — Australian SaaS** (Essential Eight + SOC 2): certification campaign,
   evidence export, full competitive scorecard.

Each post: business context → the scenario walked in the UI (real screenshots) →
the real API payloads → how it works under the hood → where we fall short.
