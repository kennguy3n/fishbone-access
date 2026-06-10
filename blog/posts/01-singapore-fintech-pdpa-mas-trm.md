# Post 1 — Singapore fintech: proving least-privilege under PDPA + MAS TRM + PCI-DSS

> Workspace: **Acme Payments** (`sg`, finance) · Personas: **Priya** (compliance
> officer), **Marcus** (CISO). Every screenshot and payload below comes from the
> live seeded workspace; the JSON is verbatim from
> [`../artifacts/payloads/`](../artifacts/payloads/) and re-running
> `make blog-capture` reproduces it.

## The business problem

Acme Payments is a 40-person payments SME. It runs a core ledger, a card data
environment (CDE), and the usual SaaS sprawl. Two regulators sit on its neck at
once:

- **PDPA** (Singapore's Personal Data Protection Act) — the *Protection
  Obligation* (s24): personal data must be guarded by "reasonable security
  arrangements," which for access means least-privilege and default-deny.
- **MAS TRM** (the Monetary Authority of Singapore's Technology Risk Management
  guidelines) — §11 access control: privileged access to financial systems must
  be tightly restricted and reviewed.
- And because it touches cardholder data, **PCI-DSS v4.0** over the CDE.

Priya's problem is not *having* controls — it's *proving* they ran, on a
schedule, with evidence an assessor will accept. Marcus's problem is blast
radius: who can reach the core ledger, and how fast can a leaver be cut off.

## Day one: apply the packs

Acme's owner applies two policy packs — `sg-pdpa-mas-trm` and `pci-dss-v4`.
Applying a pack **never enforces anything**; it materialises *draft* policies you
then simulate and promote. Here is the verbatim head of the `sg-pdpa-mas-trm`
pack as the catalogue API returns it
([`s1-sg-acme-payments-packs.json`](../artifacts/payloads/s1-sg-acme-payments-packs.json)):

```json
{
  "authority": "PDPC / Monetary Authority of Singapore",
  "frameworks": ["PDPA", "MAS TRM"],
  "id": "sg-pdpa-mas-trm",
  "name": "Singapore — PDPA + MAS TRM",
  "templates": [
    {
      "action": "grant",
      "control": "MAS TRM §11 — Access control",
      "key": "sg-privileged-control",
      "name": "Privileged access — admins only",
      "resources": ["app:core-banking"],
      "role": "admin",
      "subjects": ["role:platform-admin"]
    },
    {
      "action": "deny",
      "control": "PDPA — Reasonable security arrangements",
      "key": "sg-deny-default",
      "name": "Default-deny customer data",
      "resources": ["db:customer"],
      "subjects": ["group:all-staff"]
    }
  ]
}
```

Notice each template carries the **control it satisfies** (`MAS TRM §11`,
`PDPA — Reasonable security arrangements`). That mapping is what later lets the
evidence chain answer "which control does this policy serve?" without a human
re-deriving it.

![Acme's policy-pack library — jurisdiction packs filtered to Singapore and the frameworks it touches](../artifacts/screenshots/s1-sg-packs.png)

## The dashboard: who can reach what

After simulate-and-promote, the workspace has **6 active policies, 0 drafts**.
The dashboard is deliberately blunt: "Who can reach what — and what still needs
testing before rollout."

![Acme Payments dashboard — 6 active policies, 0 drafts, 1 open access request](../artifacts/screenshots/s1-sg-dashboard.png)

The policy list shows the mix the two packs produced — grants for the
service-team and platform-admin paths, and **default-deny** rows that are the
spine of the PDPA posture:

![Acme's access policies — grants and default-deny rows, each Active](../artifacts/screenshots/s1-sg-policies.png)

Every one of those promotions is gated. Promotion is the **strongest gate in the
API**: RBAC permission **+** a session MFA claim **+** a *fresh* step-up TOTP code
(RFC 6238, 30-second period, anti-replay). The seed paces promotions to the rate
the security model genuinely allows — it does not weaken the verifier to go
faster.

## The lifecycle leaves evidence — as a side effect

Acme then runs the access lifecycle: privileged ledger-admin and reconciliation
requests are approved and provisioned, a PCI CDE audit request is filed, a MAS
TRM privileged-access review runs, and a PCI-DSS certification campaign closes.
None of this is "compliance work" bolted on — it's normal operations, and the
evidence falls out of it.

The MAS TRM review is real and it actually **revoked** a grant
([`s1-sg-acme-payments-review-report.json`](../artifacts/payloads/s1-sg-acme-payments-review-report.json)):

```json
{
  "report": {
    "name": "Q2 2026 MAS TRM privileged-access review",
    "total": 2, "certified": 1, "revoked": 1, "escalated": 0, "pending": 0,
    "state": "active"
  }
}
```

The PCI-DSS certification campaign closed with a revoke too — every item decided
([`s1-sg-acme-payments-campaign-report.json`](../artifacts/payloads/s1-sg-acme-payments-campaign-report.json)):

```json
{
  "name": "Q2 2026 PCI-DSS v4 cardholder-data certification",
  "framework": "PCI-DSS", "state": "closed",
  "all_decided": true, "total": 1, "certified": 0, "revoked": 1, "overdue": false
}
```

## The compliance view: control coverage you didn't hand-assemble

Open **Compliance evidence** and pick PCI-DSS. The system maps the audit chain
onto framework controls and tells you, honestly, which are covered and which are
not:

![Acme's PCI-DSS coverage — 4 of 5 controls covered, with one honestly uncovered](../artifacts/screenshots/s1-sg-compliance-pci-dss.png)

This is the verbatim coverage the export embeds
([`s1-sg-acme-payments-evidence-pack-manifest.json`](../artifacts/payloads/s1-sg-acme-payments-evidence-pack-manifest.json)):

```json
{
  "coverage": {
    "framework": "PCI-DSS",
    "controls_covered": 4, "controls_total": 5, "evidence_total": 35,
    "controls": [
      { "id": "7.2",   "covered": true,  "evidence_count": 15, "title": "Least-privilege access control system" },
      { "id": "7.2.4", "covered": true,  "evidence_count": 4,  "title": "Access reviewed at least every 6 months" },
      { "id": "8.1.3", "covered": true,  "evidence_count": 9,  "title": "Access for terminated users revoked promptly" },
      { "id": "8.2",   "covered": true,  "evidence_count": 8,  "title": "Access provisioned on authorization" },
      { "id": "10.2",  "covered": false, "evidence_count": 0,  "title": "Audit trail of access to system components" }
    ]
  }
}
```

The same page also renders SOC 2's logical-access controls from the *same* chain
— one set of operations, mapped to multiple frameworks:

![Acme's SOC 2 logical-access coverage from the same evidence chain](../artifacts/screenshots/s1-sg-compliance-soc2.png)

## Under the hood: the tamper-evident chain

The number that matters to an auditor is not "61 events" — it's that the **61
events form an unbroken hash chain**. Each record links to the previous by
SHA-256; the verifier recomputes every link
([`s1-sg-acme-payments-chain-verify.json`](../artifacts/payloads/s1-sg-acme-payments-chain-verify.json)):

```json
{ "length": 61, "ok": true, "status": "valid", "workspace_id": "6343e869-8ad8-4e82-a36c-7f441e398bb8" }
```

When Acme exports the **PCI-DSS evidence pack**, the manifest carries a
`content_sha256` over the whole pack plus a per-file SHA-256, and the export
*itself* is step-up-MFA-gated and recorded back onto the chain. The pack is a
ZIP of newline-delimited JSON (`evidence.jsonl` with all 61 records,
`access-grants.jsonl`, `certification-*.jsonl`, `policies.jsonl`,
`chain-verification.json`, and an auditor README). An auditor can re-hash the
files and match the manifest offline — no trust in Acme's word required.

## i18n is not an afterthought

The same seeded data re-renders in 12 locales. Here is Acme's dashboard in
Simplified Chinese — the *same* 6 policies, same counts, fully translated chrome:

![Acme's dashboard in Simplified Chinese — same data, translated UI](../artifacts/screenshots/s1-sg-dashboard-zh-Hans.png)

For a Singapore SME with a multilingual workforce, that is the difference between
a control an operator actually understands and one they click through blindly.

## Where we fall short

Be honest about the screenshots above:

- **PCI-DSS control 10.2 ("audit trail of access to system components") is
  uncovered — 0 records.** fishbone-access records *its own* governance actions
  tamper-evidently, but it does **not** ingest the runtime access logs of the
  core-banking app. It proves the access was *authorised and reviewed*, not that
  every *read* of a card record was logged. That last mile needs a SIEM or the
  app's own audit trail.
- **No privileged session recording.** The MAS TRM review proves an admin grant
  was *certified or revoked*; it does not record the admin's keystrokes inside
  core-banking. There is no session proxy here.
- **Connector depth is shallow in-demo.** Stripe / Salesforce / GitHub register
  but sit `pending` — the catalogue breadth (201 providers) is real, but the
  deep provisioning operations per provider are not all production-grade yet.

## How a buyer should compare this

For an SME like Acme, the honest competitive picture:

| Capability | fishbone-access | Okta IGA | SailPoint | CyberArk |
| --- | --- | --- | --- | --- |
| Jurisdiction packs (PDPA/MAS TRM out of the box) | ✅ curated | ⚠️ build your own | ⚠️ build your own | ❌ |
| Tamper-evident, re-verifiable evidence export | ✅ hash-chain + manifest | ⚠️ reports, not chained | ⚠️ reports | ⚠️ |
| Step-up MFA on promote **and** export | ✅ | ⚠️ on some admin actions | ⚠️ | ✅ |
| Privileged **session recording** | ❌ | ❌ (needs Okta PAM) | ❌ | ✅ core strength |
| Access certifications / campaigns | ✅ | ✅ | ✅ deepest (SoD analytics) | ⚠️ |
| SME pricing / time-to-value | ✅ single console, days | ⚠️ per-user, weeks | ❌ enterprise, months | ❌ enterprise |

**The honest read:** SailPoint and Saviynt out-govern us on separation-of-duties
analytics and deep certifications, and CyberArk owns privileged *session*
control outright — if Acme's core risk were an admin's live keystrokes in
core-banking, CyberArk is the right tool. Where fishbone-access wins for an SME
is **time-to-defensible-evidence**: the PDPA + MAS TRM pack, the hash-chained
chain, and a re-verifiable PCI-DSS export are there on day one, in one console,
without an integration project. For a 40-person payments shop that needs to pass
an assessment next quarter — not stand up an IGA program over two years — that
trade is usually the right one. Just don't buy us expecting CyberArk's session
vault; buy the tool whose strength matches your top risk.

---

*Next: [Post 2 — US healthcare](02-us-healthcare-hipaa-ccpa.md), where the leaver
kill switch fires for real — and partially fails, on purpose, in the demo.*
