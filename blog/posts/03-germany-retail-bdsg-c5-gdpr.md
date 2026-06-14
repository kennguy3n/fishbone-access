# Post 3 — German retail: four frameworks, one fabric, rendered in German

> Workspace: **Initech Retail** (`de`, retail) · Personas: **Priya**
> (compliance officer), **Dmitri** (IT admin). Payloads verbatim from
> [`../artifacts/payloads/`](../artifacts/payloads/).

## The business problem

Initech Retail is a German omni-channel retailer. It is in scope for **four**
overlapping regimes at once:

- **BDSG** — Germany's Federal Data Protection Act (the national complement to
  GDPR).
- **BSI C5** — the German cloud-security catalogue assurance customers ask for.
- **GDPR** — Article 15 access requests, least-privilege over personal data.
- **PCI-DSS v4.0** — because it takes card payments at POS and online.

Priya's nightmare is **duplication**: four auditors, four spreadsheets, the same
control re-evidenced four times. The whole pitch of fishbone-access here is that
*one* set of access operations should answer *all four* frameworks from *one*
evidence chain.

## The richest policy set in the series

Initech applies three packs — `de-bdsg-c5`, `gdpr-personal-data`, `pci-dss-v4` —
producing the largest active policy set of any workspace: **8 active policies, 0
drafts**, over a fabric of **GitHub** (e-commerce), **Datadog** (observability),
**Azure** (cloud infra), and a **manual SAP retail-POS** target.

![Initech Retail dashboard — 8 active policies across BDSG, C5, GDPR, PCI-DSS](../artifacts/screenshots/s3-de-dashboard.png)

The connector catalogue is faceted so Dmitri can find providers by category —
the live facets include `Cloud Infra`, `DevOps`, `Observability`, `ERP`,
`IAM/PAM`, `SIEM`, `Secrets/Vault`, and more
([`s3-de-initech-retail-catalogue-facets.json`](../artifacts/payloads/s3-de-initech-retail-catalogue-facets.json)).

## One chain, four framework maps

This is the headline. Initech ran *one* lifecycle — provision a store manager and
a CDE-maintenance engineer, file a GDPR Article 15 export request, run a BSI C5 +
GDPR review, close an ISO 27001 certification campaign, open a recorded
privileged session, and detect a standing SoD conflict. The **same evidence
chain (93 records)** then projects onto every framework's control set. Here is the console's
compliance view, in **German** (locale `de`) — the same data, translated chrome:

![Initech's compliance evidence in German — control coverage from one chain](../artifacts/screenshots/s3-de-compliance-de.png)

And the verbatim coverage maps, all from that one chain:

**SOC 2** ([`coverage-soc2`](../artifacts/payloads/s3-de-initech-retail-coverage-soc2.json)) — 6 / 6:
```json
[
  { "id": "CC6.1", "covered": true, "evidence_count": 22, "title": "Logical access security — least-privilege policy enforced" },
  { "id": "CC6.2", "covered": true, "evidence_count": 11, "title": "Access provisioned on authorization" },
  { "id": "CC6.3", "covered": true, "evidence_count": 9,  "title": "Access modified/removed when no longer required" },
  { "id": "CC6.7", "covered": true, "evidence_count": 7,  "title": "Privileged access monitored" },
  { "id": "CC7.2", "covered": true, "evidence_count": 6,  "title": "Access reviewed/certified periodically" },
  { "id": "CC7.3", "covered": true, "evidence_count": 2,  "title": "Orphan / anomalous access detected and dispositioned" }
]
```

**ISO 27001 Annex A** ([`coverage-iso27001`](../artifacts/payloads/s3-de-initech-retail-coverage-iso27001.json)) — 5 / 5:
```json
[
  { "id": "A.5.15", "covered": true, "evidence_count": 16, "title": "Access control policy" },
  { "id": "A.5.16", "covered": true, "evidence_count": 7,  "title": "Identity lifecycle management" },
  { "id": "A.5.18", "covered": true, "evidence_count": 17, "title": "Access rights provisioned, reviewed and removed" },
  { "id": "A.8.2",  "covered": true, "evidence_count": 7,  "title": "Privileged access rights monitored" },
  { "id": "A.8.15", "covered": true, "evidence_count": 1,  "title": "Tamper-evident logging" }
]
```

**PCI-DSS** ([`coverage-pci-dss`](../artifacts/payloads/s3-de-initech-retail-coverage-pci-dss.json)) — 5 / 5, same shape as Post 1.

The point is not the absolute numbers — it's that **one operation feeds three
maps**. Promoting the least-privilege policy lit `CC6.1` *and* `A.5.15` *and*
`7.2` simultaneously. Priya stops re-evidencing the same control four times.

## Catching a PCI toxic combination before it lands

Initech's PCI-DSS exposure is concentrated in one rule: a store manager must not
also hold **cardholder-data** access. That is a textbook separation-of-duties
conflict, and it is encoded as a rule the engine enforces at simulation time
([`s3-de-initech-retail-sod-rules.json`](../artifacts/payloads/s3-de-initech-retail-sod-rules.json)):

```json
{
  "name": "Store-manager must not hold cardholder-data access", "severity": "critical",
  "resource_a": "pos:store-manager", "role_a": "operator",
  "resource_b": "pos:cardholder-data", "role_b": "operator"
}
```

Before a grant that would combine those two, the access **simulation** returns a
`catastrophic` verdict naming the exact rule — so the dangerous change is stopped
in the *what-if*, not discovered in next year's PCI assessment
([`s3-de-initech-retail-sod-simulation.json`](../artifacts/payloads/s3-de-initech-retail-sod-simulation.json)):

```json
{ "impact": { "catastrophic": true,
    "catastrophic_reasons": ["introduces high/critical separation-of-duties toxic combination(s)"],
    "sod_violations": [
      { "rule_name": "Store-manager must not hold cardholder-data access", "severity": "critical",
        "held":        { "resource": "pos:store-manager",   "role": "operator" },
        "conflicting": { "resource": "pos:cardholder-data", "role": "operator" } }
    ] } }
```

It is **not** SailPoint-grade entitlement-mining across thousands of roles — it
is rule-based toxic-combination detection wired into the same simulate-then-promote
gate the policy lifecycle already uses. For a mid-size retailer with a handful of
known-dangerous combinations, that is exactly the right shape.

And the *standing* sweep records the violation when a subject actually holds
both halves — `sod_anomalies = 1`, the `CC7.3` evidence
([`s3-de-initech-retail-sod-anomalies.json`](../artifacts/payloads/s3-de-initech-retail-sod-anomalies.json)):

```json
{ "detail": { "anomaly_kind": "sod_violation",
    "held":        { "resource": "pos:store-manager",   "role": "operator" },
    "conflicting": { "resource": "pos:cardholder-data", "role": "operator" } } }
```

## The privileged session is recorded

Initech also opens a JIT-leased session to the POS bastion and records it through
the production `IORecorder` — `pam_sessions = 1`, replayable over
`GET /pam/sessions/96c5ba01-4e0b-4ebf-934e-de0fd292f9dd/replay`, digest on the
chain. That is what covers `CC6.7` / `A.8.2` ("privileged access monitored").
The honest residual: the captured commands are representative I/O against a
bastion target (no live SSH daemon in the demo), proving the record-and-replay
pipeline rather than `pos_admin`'s real keystrokes in the SAP MySQL box.

## Privileged access to the POS estate

The SAP POS database (MySQL) and its Azure jump host are privileged targets, not
SaaS apps. Initech registers them with a 30-minute JIT lease ceiling
([`s3-de-initech-retail-pam-targets.json`](../artifacts/payloads/s3-de-initech-retail-pam-targets.json)):

```json
[
  { "name": "SAP POS database (MySQL)", "protocol": "mysql",
    "address": "sap-pos-db-1.initech.internal:3306", "username": "pos_admin",
    "require_mfa": true, "lease_ttl_seconds": 1800 },
  { "name": "Azure POS jump host (de-pos-1)", "protocol": "ssh",
    "address": "pos-jump-1.initech.internal:22", "username": "pos-ops",
    "require_mfa": true, "lease_ttl_seconds": 1800 }
]
```

And the seasonal headcount spike that every retailer faces is handled as a
contractor grant — a POS integrator with a sponsor and a built-in expiry, not a
permanent account someone forgets to remove
([`s3-de-initech-retail-contractor-grants.json`](../artifacts/payloads/s3-de-initech-retail-contractor-grants.json)):

```json
{ "display_name": "Seasonal POS integrator", "contractor_user_id": "ext-pos-integrator@vendor.example",
  "resource_ref": "pos:store-manager", "role": "operator", "sponsor_id": "de-admin", "state": "active" }
```

## Where we fall short

Four controls that are easy to leave empty are covered here, and we are precise
about how:

- **`CC6.7` / `A.8.2` "privileged access monitored" — covered.**
  `pam_sessions = 1`: a real JIT-leased session is recorded through the production
  `IORecorder`, anchored on the chain and replayable over the API. Residual: the
  recorded I/O is representative commands against a bastion target — the demo has
  no live SSH daemon — so it proves the recording pipeline, not `pos_admin`'s real
  keystrokes inside the SAP MySQL box. In-path against a reachable upstream the
  same recorder captures the real wire.
- **`CC7.3` "anomalous access detected and dispositioned" — covered via the
  standing SoD anomaly.** `sod_anomalies = 1`: a subject really holds both halves
  of the toxic combination and the sweep detects + dispositions it. Note the
  **orphan** scan still ran and found **0 orphans** (honest — no orphan to
  disposition); the `CC7.3` evidence comes from the standing SoD anomaly, not
  behavioural analytics.
- **`A.8.15` "tamper-evident logging" — covered.** The evidence-pack export runs
  *before* the chain is snapshotted, so `evidence_exported` is anchored in the
  verified chain.
- **SoD is rule-based, not analytics.** The check is real, pre-commit *and*
  standing — but it evaluates *declared rules*; it does not *mine* the entitlement
  graph to discover unknown conflicts the way SailPoint/Saviynt do. For a *large*
  retailer with conflicts nobody has enumerated, that mining is the gap that
  matters — see the comparison below.

## How a buyer should compare this

| Capability | fishbone-access | SailPoint | Saviynt | Okta IGA |
| --- | --- | --- | --- | --- |
| One chain → many framework maps (BDSG/C5/GDPR/PCI at once) | ✅ built-in | ⚠️ via config + add-ons | ⚠️ via config | ⚠️ limited |
| German + EU jurisdiction packs out of the box | ✅ `de-bdsg-c5`, GDPR | ⚠️ build your own | ⚠️ | ⚠️ |
| SoD toxic-combo check at simulation (rule-based) | ✅ pre-commit `catastrophic` | ✅ deepest analytics | ✅ strong | ⚠️ |
| SoD entitlement-mining **analytics** at scale | ⚠️ declared rules (pre-commit + standing) | ✅ deepest | ✅ strong | ⚠️ |
| Orphan/anomaly **analytics** (beyond detection) | ⚠️ standing SoD anomaly + orphan detection; no behavioural ML | ✅ | ✅ | ⚠️ |
| Privileged JIT **lease** lifecycle | ✅ governed + chained | ⚠️ | ⚠️ (CPAM) | ⚠️ |
| Privileged **session** recording (replayable, chained) | ⚠️ recorded; demo upstream is a bastion | ⚠️ (partner) | ⚠️ (CPAM) | ❌ |
| Multi-locale (de native) | ✅ 12 locales | ⚠️ | ⚠️ | ✅ |
| SME fit (one console, weeks not quarters) | ✅ | ❌ enterprise | ❌ enterprise | ⚠️ |

**The honest read:** we catch *declared* toxic combinations at simulation
time — enough for a retailer with a known set of dangerous pairings like
store-manager-vs-cardholder-data. But for a *large* retailer with thousands of
roles and conflicts nobody has enumerated yet, **SailPoint** or **Saviynt** are
the right answer — their SoD *mining* and orphan/anomaly analytics discover the
conflicts you didn't know to write down, and that is exactly the `CC7.3` gap
above. What they are *not* is fast or cheap for a
mid-size German retailer that needs BDSG + C5 + GDPR + PCI answered next quarter.
fishbone-access ships those four packs and the one-chain-many-maps projection on
day one, in German, in one console. Buy SailPoint if your risk is *toxic
combinations across thousands of entitlements*; buy us if your risk is *proving
four overlapping frameworks without a two-quarter integration project*.

---

*Next: [Post 4 — Vietnam logistics](04-vietnam-logistics-pdpd-decree13.md): the
"day one" story in an emerging-compliance market, in Vietnamese.*
