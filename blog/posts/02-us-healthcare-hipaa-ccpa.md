# Post 2 — US healthcare: HIPAA minimum-necessary, CCPA, and a leaver kill switch that fails on purpose

> Workspace: **Globex Health** (`us`, healthcare) · Personas: **Sofia**
> (security engineer), **Dmitri** (IT admin). Payloads are verbatim from
> [`../artifacts/payloads/`](../artifacts/payloads/).

## The business problem

Globex Health is a digital-health SME holding electronic protected health
information (ePHI). Two regimes apply:

- **HIPAA Security Rule** — the *minimum-necessary* standard: a workforce member
  may touch only the ePHI their job requires, and access for terminated users
  must be revoked promptly.
- **CCPA / CPRA** — California consumers can demand to know and delete their
  data, which means Globex must be able to find *who can reach* a consumer
  record and prove it was provisioned on authorization.

Sofia owns the part everyone gets wrong: the **leaver**. A clinician who quits on
Friday must be off every system by Friday evening — SSO, document store, and the
EHR role — or it's a reportable gap. Dmitri wants this to happen without a
bespoke offboarding script per app.

## The dashboard

Globex seeds to **5 active policies, 0 drafts**, built from the
`hipaa-security-rule` and `us-ccpa-cpra` packs over a lean fabric: **Okta**
(workforce SSO), **Box** (clinical documents), and a **manual Epic EHR**
clinical-role target — because the EHR has no self-service provisioning API, the
manual connector fulfils it locally and still records the lifecycle.

![Globex Health dashboard — 5 active HIPAA/CCPA policies](../artifacts/screenshots/s2-us-dashboard.png)

## Access requests carry risk

The access-request queue is where minimum-necessary becomes operational. Each
request is risk-scored before a human ever sees it:

![Globex access requests — clinician, billing, and a PHI-export auditor request, each risk-tiered](../artifacts/screenshots/s2-us-access-requests.png)

The HIPAA ePHI access review then runs over the resulting grants and makes real
decisions — one certified, one revoked
([`s2-us-globex-health-review-report.json`](../artifacts/payloads/s2-us-globex-health-review-report.json)):

```json
{
  "report": {
    "name": "Q2 2026 HIPAA ePHI access review",
    "total": 2, "certified": 1, "revoked": 1, "escalated": 0, "pending": 0,
    "state": "active"
  }
}
```

The certification campaign closes with every item decided
([`s2-us-globex-health-campaign-report.json`](../artifacts/payloads/s2-us-globex-health-campaign-report.json)):

```json
{
  "name": "Q2 2026 HIPAA Security Rule certification",
  "state": "closed", "all_decided": true, "total": 1, "revoked": 1, "overdue": false
}
```

## The leaver kill switch — and why it *should* report failure here

This is the most honest screen in the whole series. When a leaver is processed,
the kill switch does not "delete a user." It **sweeps every layer** that can cut
off access and records each layer's result on the audit chain. Here are the
verbatim leaver events from Globex's evidence chain
([`s2-us-globex-health-evidence.json`](../artifacts/payloads/s2-us-globex-health-evidence.json),
records 54–59):

```
jml.leaver.grant_revoke.done          ← local grants revoked          ✅
jml.leaver.team_remove.done           ← removed from teams            ✅
jml.leaver.iam_core_disable.skipped   ← no iam-core identity to disable
jml.leaver.session_revoke.failed      ← Okta session revoke           ❌
jml.leaver.scim_deprovision.failed    ← Box SCIM deprovision          ❌
jml.leaver.identity_disable.done      ← local identity disabled       ✅
```

Two layers **failed**, and that is correct. In this self-contained demo the live
SaaS connectors (Okta, Box) carry *placeholder* credentials and there is no real
upstream to reach — so `session_revoke` and `scim_deprovision` genuinely cannot
confirm revocation. The kill switch **still** revokes the grants and disables the
identity locally, and it records the *full layered result* including the
failures. It reports **partial failure** rather than a green check it cannot
honestly give.

A system that printed "leaver complete ✅" here would be lying. fishbone-access
surfaces the partial result so Sofia knows exactly which upstream still needs a
manual cut-off. (Point the same connectors at real Okta/Box tenants with valid
credentials and those two lines flip to `.done`.)

You can see the same layered events on the compliance evidence timeline in the
console (the `Kill Switch Fired` rows), each linked into the hash chain.

## The compliance view

Globex's SOC 2 logical-access coverage from the same chain — provisioning,
review, and revocation controls covered; the privileged-monitoring control
honestly empty:

![Globex SOC 2 logical-access coverage](../artifacts/screenshots/s2-us-compliance-soc2.png)

## Where we fall short

- **The two failed kill-switch layers are real gaps in the demo**, not cosmetic.
  Without real upstream credentials, fishbone-access cannot *prove* the Okta
  session and Box account were killed — it can only prove it tried and that the
  local grant is gone.
- **No ePHI-read logging.** Like Post 1's PCI 10.2 gap, we prove access was
  *authorised and reviewed*, not that every read of a patient record was logged.
  HIPAA audit-control (§164.312(b)) over the EHR itself still needs the EHR's
  audit log or a SIEM.
- **CCPA "delete" is not executed.** We can show *who could reach* a consumer
  record (the access surface) and that grants were certified/revoked; we do not
  run the data-deletion in the downstream app.

## How a buyer should compare this

| Capability | fishbone-access | Okta IGA | SailPoint | StrongDM / Teleport |
| --- | --- | --- | --- | --- |
| Multi-layer leaver sweep with honest partial-failure report | ✅ records every layer | ⚠️ lifecycle, less explicit on partials | ✅ deep deprovision | ❌ (infra access only) |
| HIPAA/CCPA packs out of the box | ✅ | ⚠️ build your own | ⚠️ build your own | ❌ |
| Real-time SaaS deprovision at scale | ⚠️ depends on connector depth | ✅ Okta's home turf | ✅ | ❌ |
| Infra (DB/SSH/k8s) access brokering for ePHI stores | ❌ | ❌ | ❌ | ✅ core strength |
| ePHI **read** audit trail | ❌ needs SIEM | ❌ | ❌ | ⚠️ session logs |

**The honest read:** if Globex's biggest exposure is the *SaaS* lifecycle — Okta
+ Box + an EHR — Okta IGA is the incumbent with the deepest native deprovision on
its own platform, and SailPoint goes deeper still on certification analytics. If
the exposure is engineers reaching the *database* that stores ePHI, Teleport or
StrongDM broker and record that far better than we do. Where fishbone-access wins
is the **honest, layered offboarding record** plus HIPAA/CCPA packs in one SME
console: the partial-failure report is exactly the artifact an auditor wants when
they ask "show me a termination." We'd rather show a true ❌ than a fake ✅ — and
that is the whole point of the chain.

---

*Next: [Post 3 — German retail](03-germany-retail-bdsg-c5-gdpr.md): four
overlapping frameworks over one connector fabric, rendered in German.*
