# Post 5 — UAE finance: privileged access to core banking, and the honest limits of our PAM story

> Workspace: **Northwind Finance** (`ae`, finance) · Personas: **Sofia**
> (security engineer), **Marcus** (CISO). Payloads verbatim from
> [`../artifacts/payloads/`](../artifacts/payloads/). Locale: Arabic (RTL).

## The business problem

Northwind Finance is a UAE wealth-management firm. Its crown jewel is a
**Temenos T24 core-banking** system, and two regimes govern who may touch it:

- **UAE PDPL** — the Personal Data Protection Law (Federal Decree-Law 45/2021),
  enforced by the UAE Data Office: security of processing and access restriction
  over personal data.
- **Dubai DESC** — the Dubai Electronic Security Center's Information Security
  Regulation (ISR): strict privileged-access control for regulated entities.
- Plus **ISO 27001 Annex A** as the assurance baseline customers expect.

Sofia's whole job here is **privileged access**: the handful of admins who can
reach T24. Marcus needs to show DESC that privileged access is restricted,
reviewed, and revoked. This post is where fishbone-access does real governance
*and* where it most clearly hits its ceiling — so it's the right place to be
blunt about PAM.

## The packs cite the regulators directly

Northwind applies `ae-pdpl-desc` and `iso27001-annexa`, yielding **6 active
policies**. The PDPL/DESC templates name the exact articles
([`s5-ae-northwind-finance-packs.json`](../artifacts/payloads/s5-ae-northwind-finance-packs.json)):

```
PACK ae-pdpl-desc — "UAE — PDPL + DESC"
     authority: UAE Data Office / Dubai Electronic Security Center
  • grant  "Authorised staff → personal data"   control: UAE PDPL Art. 9 — Security of processing
  • grant  "Privileged access — admins only"    control: DESC ISR — Access control
  • deny   "Default-deny personal data"          control: UAE PDPL Art. 9 — Access restriction
```

![Northwind Finance dashboard — 6 PDPL/DESC/ISO policies, privileged-access theme](../artifacts/screenshots/s5-ae-dashboard.png)

## Right-to-left, natively

The same workspace in Arabic (`ar`) — and this is a genuine engineering test,
because Arabic is **right-to-left**. The entire layout mirrors: the navigation
rail moves to the right, the content flows RTL, the chrome is fully translated.
This is the same six policies and the same counts, re-rendered:

![Northwind's dashboard in Arabic — full RTL mirroring, sidebar on the right](../artifacts/screenshots/s5-ae-dashboard-ar.png)

For a Dubai firm, RTL that *actually mirrors* (rather than just translating
left-to-right strings) is the difference between a usable console and a broken
one.

## The privileged-access review is real

The DESC privileged-access review ran over the T24 admin grants and made real
decisions — one certified, one revoked
([`s5-ae-northwind-finance-review-report.json`](../artifacts/payloads/s5-ae-northwind-finance-review-report.json)):

```json
{
  "report": {
    "name": "Q2 2026 DESC privileged-access review",
    "total": 2, "certified": 1, "revoked": 1, "state": "active"
  }
}
```

And the ISO 27001 Annex A coverage from the chain
([`s5-ae-northwind-finance-coverage-iso27001.json`](../artifacts/payloads/s5-ae-northwind-finance-coverage-iso27001.json)):

```json
[
  { "id": "A.5.15", "covered": true,  "evidence_count": 12, "title": "Access control policy" },
  { "id": "A.5.16", "covered": true,  "evidence_count": 7,  "title": "Identity lifecycle management" },
  { "id": "A.5.18", "covered": true,  "evidence_count": 14, "title": "Access rights provisioned, reviewed and removed" },
  { "id": "A.8.2",  "covered": false, "evidence_count": 0,  "title": "Privileged access rights monitored" },
  { "id": "A.8.15", "covered": false, "evidence_count": 0,  "title": "Tamper-evident logging" }
]
```

## Where we fall short — and this is the big one

Look at `A.8.2`: **"Privileged access rights monitored" — 0 records.** This is
not a demo artifact; it is a **product boundary**, and on the highest-risk
workspace in the series it matters most:

- **There is no privileged-session proxy or recording.** fishbone-access proves
  the T24 admin grant was *authorised, reviewed, and revoked*. It does **not**
  sit in the connection path, vault the credential, broker the session, or record
  the admin's keystrokes inside T24. The **PAM targets** screen in this workspace
  is empty — no targets registered — because that brokering layer isn't what this
  product does.
- **SSO is not enforced for this connector** either
  ([`s5-ae-northwind-finance-sso-status.json`](../artifacts/payloads/s5-ae-northwind-finance-sso-status.json)
  reports `"enforced": false, "supported": false`). We surface that honestly
  rather than implying an SSO guarantee we don't provide on that path.
- **`A.8.15` "tamper-evident logging" reads uncovered** despite the hash chain —
  same ISO-mapping gap as Post 3.

For a wealth-management firm whose top risk is *what an admin does inside core
banking once connected*, fishbone-access governs the **grant** but not the
**session**. That is precisely the line where a dedicated PAM tool is not
optional.

## How a buyer should compare this

| Capability | fishbone-access | CyberArk | StrongDM | Teleport | Okta IGA |
| --- | --- | --- | --- | --- | --- |
| Privileged credential vaulting | ❌ | ✅ core | ⚠️ brokered | ⚠️ cert-based | ❌ |
| Live privileged **session recording** | ❌ | ✅ core | ✅ | ✅ | ❌ |
| Session isolation / in-path brokering | ❌ | ✅ | ✅ core | ✅ core | ❌ |
| Govern the privileged **grant** (request→review→revoke) | ✅ | ⚠️ add-on | ❌ | ❌ | ✅ |
| PDPL/DESC packs + framework evidence | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| Arabic RTL console | ✅ | ⚠️ | ❌ | ❌ | ⚠️ |

**The honest read:** for Northwind's core risk — privileged sessions inside
Temenos T24 — **CyberArk** is the correct purchase, full stop. Credential
vaulting, session isolation, and keystroke recording are its reason to exist, and
they fill the exact `A.8.2` hole our own coverage map shows as empty.
**StrongDM** and **Teleport** are the modern, engineer-friendly alternatives if
the privileged targets are databases, SSH, and Kubernetes rather than a banking
mainframe. Where fishbone-access fits is the **governance** wrapper around those
tools: the PDPL/DESC packs, the request→review→revoke lifecycle, the certified
evidence chain, and an Arabic RTL console. The mature architecture for Northwind
is **fishbone-access for governance + CyberArk for the session** — and we'd tell
a buyer exactly that rather than pretend our 0-record `A.8.2` is a win.

---

*Next: [Post 6 — Australian SaaS](06-australia-saas-essential-eight-soc2.md): the
SOC 2 evidence export an auditor can re-verify offline — and the full competitive
scorecard.*
