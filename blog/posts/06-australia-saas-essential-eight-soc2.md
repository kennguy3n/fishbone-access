# Post 6 — Australian SaaS: a SOC 2 evidence pack an auditor can re-verify offline

> Workspace: **Contoso SaaS** (`au`, saas) · Personas: **Marcus** (CISO),
> **Aisha** (external auditor). Payloads verbatim from
> [`../artifacts/payloads/`](../artifacts/payloads/). This is the finale and the
> full competitive scorecard.

## The business problem

Contoso is an Australian SaaS vendor. To sell upmarket it must pass a **SOC 2
Type II** audit, and to satisfy local expectations it maps to the ACSC
**Essential Eight** — specifically *restrict administrative privileges*. The
whole sale hinges on one moment: an auditor (Aisha) asks for evidence, and
Contoso must hand her something she can **verify herself**, offline, without
trusting Contoso's dashboard.

That artifact — a re-verifiable evidence pack — is what this post is about, and
it's the capability that most cleanly separates fishbone-access from a pile of
screenshots in a shared drive.

## The setup

Contoso applies `au-privacy-e8` and `soc2-logical-access`, yielding **6 active
policies** over **GitHub** (product eng), **GCP** (production), **Slack**
(engineering), and a **manual billing-console** target. The policy names tell the
Essential-Eight story directly — *Restrict administrative privileges*,
*Privileged prod access — admins only*, *Deny-all to production by default*.

![Contoso SaaS dashboard — 6 SaaS policies, Essential Eight admin-restriction theme](../artifacts/screenshots/s6-au-dashboard.png)

Contoso then runs the lifecycle: RevOps and time-boxed deploy grants, a SOC 2
evidence-sampling auditor request, a SOC 2 Type II recertification review, and a
**closed SOC 2 certification campaign**.

## The export — the moment that matters

On the **Compliance evidence** page, Contoso clicks **Export SOC 2 pack**. Two
things happen that you can see in the live console:

1. A ZIP downloads (here, `evidence-pack-SOC_2.zip`).
2. A toast confirms **"Evidence pack exported — Digest `f5eff33453…` recorded
   on the audit chain"**, and the export *itself* appears as a new
   `compliance.export` event on the timeline (record `#99` in the screenshot —
   the newest row on the chain).

![Contoso's SOC 2 compliance-evidence page — 99 records verified, chain intact, 6/6 controls covered, 49 evidence records, export button top-right](../artifacts/screenshots/s6-au-compliance-export.png)

The export is **step-up-MFA-gated** — it consumes a fresh TOTP code, the same
strongest-gate treatment as policy promotion — and it is *self-recording*:
exporting evidence is itself an evidence event. The page header confirms the
chain is **intact** and every record's SHA-256 link was recomputed and matched.

## What's in the pack — and why Aisha trusts it

The committed manifest is the contract
([`s6-au-contoso-saas-evidence-pack-manifest.json`](../artifacts/payloads/s6-au-contoso-saas-evidence-pack-manifest.json)):

```json
{
  "framework": "SOC 2",
  "schema_version": "1.1",
  "generated_by": "au-contoso-saas-owner",
  "content_sha256": "f5eff33453816b1961068196047ef5f9c1017287a8ea64e89e04b3176d2aa9cd",
  "chain_verification": { "length": 98, "ok": true, "status": "valid" },
  "coverage": { "framework": "SOC 2", "controls_covered": 6, "controls_total": 6, "evidence_total": 48 },
  "files": [
    { "name": "evidence.jsonl",              "rows": 98 },
    { "name": "pam-recordings.jsonl",        "rows": 1 },
    { "name": "access-grants.jsonl",          "rows": 6 },
    { "name": "certification-campaigns.jsonl","rows": 1 },
    { "name": "certification-items.jsonl",    "rows": 1 },
    { "name": "policies.jsonl",               "rows": 6 },
    { "name": "control-coverage.json",        "rows": 0 },
    { "name": "chain-verification.json",      "rows": 0 },
    { "name": "README.md",                    "rows": 0 }
  ]
}
```

Each file in the manifest also carries its own SHA-256. So Aisha's verification
is mechanical and needs **zero trust in Contoso**:

1. Re-hash each file → compare to the per-file `sha256` in the manifest.
2. Re-hash the whole pack → compare to `content_sha256`.
3. Replay `evidence.jsonl`'s hash chain → confirm it matches
   `chain-verification.json` (`length: 98, status: valid`).

If a single byte of any evidence record was altered after the fact, a link
breaks and the chain fails. That's the difference between "here are some
screenshots" and "here is a tamper-evident record you can independently verify."

> Note on the numbers: exporting is itself an audited event, so the pack is a
> **pre-export snapshot**. The manifest's `chain_verification` and the pack's
> `evidence.jsonl` seal the **98** records that existed at the instant of export;
> the `compliance.export` event then lands as the **99th** record on the chain
> (the newest row in the screenshot's timeline), which is why the live console
> reads **99 evidence records verified** over **49** SOC 2 evidence records. A
> pack cannot hash itself — the export it records is always the next link, and
> that link is independently re-verifiable on the chain. The manifest's
> `pam-recordings.jsonl` carries a line for the **recorded privileged session**
> (`pam_sessions = 1`), and SOC 2 coverage is the full **6 / 6** controls.
>
> One honest subtlety the digest makes concrete: every export is a fresh
> invocation, so its `content_sha256` is computed over a manifest that includes
> the moment it ran. Re-exporting an unchanged workspace therefore yields a
> *different* digest — what is invariant is the **chain** the pack carries, which
> any auditor re-verifies independently. The digest above is the one recorded by
> the export that produced this committed manifest.

## What the export actually covers — the full access surface

The reason the pack is more than policies is that Contoso runs the *whole* access
surface through the chain before exporting it:

- **PAM to production** is a JIT lease, not a shared key. The production
  PostgreSQL datastore and the GCP production VM are registered targets
  ([`s6-au-contoso-saas-pam-targets.json`](../artifacts/payloads/s6-au-contoso-saas-pam-targets.json)):
  ```json
  [
    { "name": "Production datastore (PostgreSQL)", "protocol": "postgres",
      "address": "prod-db-1.contoso-saas.internal:5432", "username": "app_ro", "require_mfa": true },
    { "name": "GCP production VM (prod-au-1)", "protocol": "ssh",
      "address": "prod-au-1.contoso-saas.internal:22", "username": "sre", "require_mfa": true }
  ]
  ```
- **The Essential-Eight "restrict admin privileges" control becomes a SoD rule**:
  whoever can deploy to production must not also hold billing-admin. The
  simulation flags the combination `catastrophic` before it lands, and the
  standing sweep records `sod_anomalies = 1` when a subject actually holds both
  `prod:deploy` and `billing:admin`
  ([`s6-au-contoso-saas-sod-simulation.json`](../artifacts/payloads/s6-au-contoso-saas-sod-simulation.json),
  [`-sod-anomalies.json`](../artifacts/payloads/s6-au-contoso-saas-sod-anomalies.json)).
- **The prod lease is followed by a recorded session** (`pam_sessions = 1`),
  replayable over `GET /pam/sessions/e6187127-648c-49b4-a1ed-d9275461f939/replay`
  and chained — the `CC6.7` evidence.
- **The on-call SRE vendor** is a time-boxed contractor grant — sponsor named,
  expiry built in ([`s6-au-contoso-saas-contractor-grants.json`](../artifacts/payloads/s6-au-contoso-saas-contractor-grants.json)):
  ```json
  { "display_name": "On-call SRE vendor", "contractor_user_id": "ext-sre-oncall@vendor.example",
    "resource_ref": "prod:deploy", "role": "operator", "sponsor_id": "au-admin", "state": "active" }
  ```

All of it — PAM leases, the contractor grant, the SoD-checked policy promotions,
the certification — is on the *same* hash chain the export re-verifies. That is
the point: the evidence pack is a single, tamper-evident record of the entire
access lifecycle, not a folder of disconnected reports.

## Where we fall short — and the line we stop at

Contoso's SOC 2 coverage is **6 / 6**, with a stated boundary on each control:

- **`CC6.7` "Privileged access monitored" — covered.** `pam_sessions = 1`: the JIT
  lease to the prod DB/VM is followed by a recorded, replayable, chain-anchored
  session. The residual (Post 5 is the full version): the recorder drives
  representative commands against a bastion target, proving the
  record-and-replay pipeline — it is not an in-path proxy capturing live keystrokes
  off the prod box.
- **`CC7.3` "Orphan / anomalous access detected and dispositioned" — covered via
  the standing SoD anomaly.** A subject really holds both halves of a toxic
  combination and the sweep detects + dispositions it. The **orphan** scan still
  ran and found 0 (honest — nothing to disposition), and we don't run behavioural
  anomaly analytics; the `CC7.3` evidence is the declared-rule SoD anomaly, not
  ML.

That 6/6 is honest because each cell is backed by a real evidence record an
auditor can open and re-verify — and the privileged-access cells come with an
explicit statement of what they do and don't prove, rather than a loose mapping.

## The full competitive scorecard

Across the whole series, here is the honest positioning:

| Capability | fishbone&#8209;access | Okta IGA | SailPoint | Saviynt | CyberArk | Teleport | StrongDM |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Jurisdiction/framework packs out of the box | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ❌ |
| One chain → many framework maps | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ❌ |
| Tamper-evident, **re-verifiable** evidence export | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| Evidence re-verify stays cheap as the chain grows (O(Δ) incremental) | ✅ | n/a | n/a | n/a | n/a | n/a | n/a |
| Step-up MFA on promote, export **and** lease approval | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ |
| Access certifications / campaigns | ✅ | ✅ | ✅✅ | ✅✅ | ⚠️ | ❌ | ❌ |
| AI-assisted risk on requests/leases (real agent, fails safe if offline) | ✅ | ⚠️ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Time-boxed contractor access (sponsor + auto-expiry) | ✅ | ⚠️ | ✅ | ✅ | ❌ | ⚠️ | ⚠️ |
| SoD toxic-combo check at simulation (rule-based) | ✅ | ⚠️ | ✅✅ | ✅✅ | ❌ | ❌ | ❌ |
| SoD entitlement-mining **analytics** at scale | ⚠️ | ⚠️ | ✅✅ | ✅✅ | ❌ | ❌ | ❌ |
| Standing SoD anomaly detection (declared-rule) | ✅ | ⚠️ | ✅✅ | ✅✅ | ❌ | ❌ | ❌ |
| Orphan/anomaly **behavioural analytics** | ❌ detect only | ⚠️ | ✅ | ✅ | ❌ | ⚠️ | ⚠️ |
| Privileged JIT **lease** lifecycle (request→approve→expire) | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ | ✅ | ✅ |
| Privileged credential vaulting | ❌ | ❌ | ❌ | ⚠️ | ✅✅ | ⚠️ | ⚠️ |
| Privileged **session recording** (replayable, chained) | ⚠️ recorded; demo upstream is a bastion | ❌ | ❌ | ⚠️ | ✅✅ live wire | ✅ | ✅ |
| Infra (DB/SSH/k8s) access brokering (in-path) | ❌ | ❌ | ❌ | ❌ | ⚠️ | ✅✅ | ✅✅ |
| Multi-locale incl. RTL | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ |
| SME fit (one console, days→weeks) | ✅ | ⚠️ | ❌ | ❌ | ❌ | ✅ | ✅ |

✅✅ = category leader · ✅ = strong · ⚠️ = partial / add-on / build-it-yourself · ❌ = not the tool's job

### How to read it

- **If your risk is recording the privileged *session* off a live wire**
  (keystrokes inside core-banking, a prod DB, Kubernetes): **CyberArk** (vault +
  session), or **Teleport / StrongDM** for modern infra access. We govern the
  JIT *lease* and record + replay a chained session, but the demo upstream is a
  bastion — we are not an in-path proxy vaulting the live credential and capturing
  real keystrokes, so pair us with one of these where in-path interception is the
  requirement.
- **If your risk is *toxic combinations* across thousands of *un-enumerated*
  entitlements:** **SailPoint** or **Saviynt**. We catch *declared* toxic
  combinations at simulation time (the `catastrophic` verdict in Posts 1, 3, 5),
  but their entitlement-*mining* finds the conflicts nobody wrote down — and their
  behavioural orphan/anomaly analytics go beyond the declared-rule standing
  anomaly we use to evidence `CC7.3`.
- **If your worry is that a verifiable chain gets *expensive* to keep proving
  as years of evidence pile up:** that is the one scaling axis where the chain
  could hurt, and the incremental verify is the answer. A full verify is O(n) in
  chain length; the incremental verify (Post 7) re-proves only the rows added
  since a trusted anchor, so an interactive dashboard pays O(Δ) per refresh and
  a periodic full sweep stays the root of trust. The `n/a` column entries are
  honest: tools that emit flat, unverifiable reports have no chain to re-verify,
  so they have neither this cost nor the guarantee that creates it.
- **If your risk is *proving framework compliance fast, as an SME*, across
  jurisdictions, with evidence an auditor can re-verify — over the full access
  surface (SaaS, internal systems, JIT-privileged DB/VM, contractors, JML):**
  that's our lane — PDPA/HIPAA/BDSG/PDPD/PDPL/Essential-Eight packs,
  one-chain-many-maps, AI-risk-scored requests, a governed privileged-lease flow,
  time-boxed contractor access, and a step-up-gated re-verifiable export, in 12
  locales including RTL, in one console.

**The honest conclusion:** fishbone-access is not trying to out-record CyberArk's
in-path session vault or out-mine SailPoint's entitlement analytics, and this
series has shown — with explicit boundaries on the `CC6.7` / `CC7.3` cells
(bastion-recorded session, declared-rule SoD anomaly) and real AI-risk verdicts
— exactly where those tools still win. What it covers is broad: SaaS and
internal-system access through one connector fabric, JIT
privileged leases to cloud VMs and databases, time-boxed contractor access,
AI-assisted risk on every request, SoD simulation that stops catastrophic grants,
JML with a layered leaver kill switch, and regulation-keyed certification with a
re-verifiable export. Its bet is that most SMEs don't fail audits for lack of a
session vault; they fail because they **can't prove the controls ran**. The whole
product is built to make that proof verifiable, multi-framework, multilingual, and
cheap enough for a 40-person company to stand up this quarter. Where it falls
short, the coverage map says so on screen — which is, in the end, the most honest
competitive claim of all. And the one place the verifiable-evidence model could
buckle at SaaS scale — the O(n) cost of re-verifying an ever-growing chain — has
an O(Δ) incremental verify, so 5,000 tenants accreting years of evidence does
not turn the cheapest guarantee in the category into the most expensive endpoint
in the product.

---

*Next: [Post 7 — Benchmarks on this VM](07-benchmarks-on-this-vm.md): what the
live control plane actually clocks on a single dev box, with the methodology and
the caveats spelled out.*

*Reproduce everything in this series with `make blog-seed`, `make blog-capture`,
`make blog-bench`, and `make blog-test` — see [`README.md`](README.md). Every
screenshot above is a real seeded page; every payload is a verbatim capture.*
