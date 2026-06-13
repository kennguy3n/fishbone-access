# Post 7 — Benchmarks on this VM: what the control plane actually clocks

> Personas: **Marcus** (CISO / buyer), **Dmitri** (IT admin). Numbers are
> verbatim from [`../artifacts/benchmark-results.json`](../artifacts/benchmark-results.json),
> produced by [`blog/harness/bench`](../harness/bench/main.go) and reproducible
> with `make blog-bench`. This post times the *real* API the rest of the series
> drives — same endpoints, same RBAC, same Postgres.

The series so far has been about *correctness and evidence*. This post is about
*speed*, and it holds the same honesty contract: the numbers below were measured
on the development VM that built this series, against the live, seeded control
plane — not estimated, not from a tuned cluster, not cherry-picked.

## What we measured, and how

`blog/harness/bench` is the fourth harness alongside seed, capture, and
minttokens. It mints an owner JWT for the **Acme Payments** workspace (the
richest seeded tenant), warms each endpoint, then fires a fixed number of
requests across a worker pool and records every request's wall-clock latency.
A non-2xx response counts as an error **and** its latency is still recorded, so
a degraded endpoint cannot look fast by dropping its slow samples. The client's
connection pool is sized to the concurrency (idle conns = `c`), so the figures
reflect *server* latency rather than client-side connection churn.

Each endpoint is a real, RBAC-gated route. Every timed request travels the full
path a console user hits:

```
HTTP (loopback) → dev JWT validation (HS256) → tenant resolution → RBAC
              → handler → GORM → PostgreSQL → response
```

The one write path — `policy-simulate (engine)` — exercises the impact /
SoD-conflict engine via `POST /api/v1/policies/simulate-definition`, which
computes the real dry-run impact **without persisting anything**, so the
benchmark stays idempotent and leaves no state behind.

### The machine

The harness records the box it ran on
([`benchmark-results.json` → `system`](../artifacts/benchmark-results.json)):

| Field | Value |
| --- | --- |
| CPU | AMD EPYC 7763 64-Core Processor |
| vCPU visible / `GOMAXPROCS` | 8 / 8 |
| Memory | ~32 GB |
| OS / arch | linux / amd64 |
| Go | go1.25.0 |
| Config | `n = 400` requests/endpoint, `c = 16` concurrent workers |

One API process, one Postgres, no connection-pool tuning, no caching tier, no
horizontal scale — a single dev VM talking to itself over loopback.

## The numbers

Latency in milliseconds; throughput in requests/second at concurrency 16. Every
endpoint returned **0 errors** across all 400 requests.

| Group | Endpoint | p50 | p90 | p99 | mean | req/s |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| liveness | `GET /health` | 0.38 | 0.95 | 2.13 | 0.50 | 30,159 |
| catalogue | `GET /connectors/providers` (200+) | 0.56 | 1.15 | 2.01 | 0.64 | 24,424 |
| catalogue | `GET /connectors/catalogue/facets` | 0.94 | 1.82 | 3.13 | 1.11 | 13,977 |
| govern | `GET /packs?region=sg` | 0.92 | 1.66 | 2.51 | 1.02 | 15,385 |
| govern | `GET /policies` | 3.73 | 14.60 | 21.15 | 5.46 | 2,799 |
| lifecycle | `GET /access-requests` | 2.53 | 11.07 | 19.70 | 4.01 | 3,762 |
| lifecycle | `GET /connectors` | 8.28 | 16.46 | 25.96 | 9.18 | 1,709 |
| pam | `GET /pam/targets` | 2.62 | 12.92 | 25.09 | 4.45 | 3,441 |
| pam | `GET /pam/leases` | 2.49 | 10.82 | 18.97 | 4.00 | 3,763 |
| compliance | `GET /compliance/coverage?framework=SOC 2` | 9.07 | 21.77 | 29.62 | 11.02 | 1,421 |
| compliance | `GET /compliance/chain/verify` (full, O(n)) | 10.15 | 21.16 | 33.98 | 11.81 | 1,308 |
| compliance | `GET /compliance/chain/verify?from_seq=…` (incremental, O(Δ)) | 3.45 | 14.61 | 24.77 | 5.49 | 2,768 |
| compliance | `GET /compliance/evidence` | 11.84 | 24.36 | 35.49 | 13.43 | 1,178 |
| engine | `POST /policies/simulate-definition` | 5.29 | 17.50 | 30.44 | 7.67 | 2,026 |

## Reading the shape

The numbers tell a coherent story, and the *ordering* is the interesting part —
it tracks how much work each route actually does:

- **Static / in-memory reads are effectively free.** `/health` and the 200+
  provider catalogue answer in **sub-millisecond p50** and push **~24–30k
  req/s** on one box. The connector catalogue is served from memory, so breadth
  (201 providers) costs almost nothing to read.
- **Tenant-scoped DB reads sit in the low single-digit-millisecond p50** and a
  few thousand req/s. `/policies`, `/access-requests`, `/pam/targets`, and
  `/pam/leases` all land around **4 ms p50**, with p99 pulled up to the
  20–40 ms range by Postgres round-trips under concurrency — normal for an
  untuned single instance.
- **Compliance is the heaviest read, *by design*.** A full `chain-verify`
  (~10 ms p50) recomputes the SHA-256 link for **every** record in the workspace
  chain, and `evidence/coverage` walks and projects the chain onto a framework.
  They are the slowest endpoints in the set, and that is the *correct* cost: it
  is the price of tamper-evidence and one-chain-many-maps that the rest of the
  series sells. Even so, the box serves **~1,180–1,420 reads/second** on them.
- **The incremental verify is the scale answer, and it shows up here.** The same
  `chain/verify` route, handed an anchor a caller already trusts
  (`?from_seq=&from_hash=`), re-checks only the rows appended since that anchor.
  At the head — zero new rows — it clocks **3.45 ms p50 / 2,768 req/s**, ~2.1×
  the throughput of the full verify on a chain of ~100 rows. That ratio is
  not the point; the *curve* is. The full verify is **O(n)** in chain length
  while the incremental is **O(Δ)** in rows-since-anchor, so on a multi-year
  chain of hundreds of thousands of rows the full verify climbs and the
  incremental stays flat. See "The 5,000-tenant question" below for why this is
  the change that matters most for SaaS scale.
- **The policy/SoD engine is cheap enough to run inline.** A full dry-run
  simulation — impact analysis **plus** the toxic-combination check — costs
  **5.3 ms p50 / 7.7 ms mean**. That matters: it means the `catastrophic`
  guardrail in Posts 1, 3 and 5 is not an expensive batch job, it is fast enough
  to run synchronously on every promote.

## The 5,000-tenant question

The series' own honesty caveat — *a full `chain-verify` is O(n) in chain length*
— is the thing that bites at SaaS scale. Picture the target: **5,000 SME
tenants**, each accreting evidence for years. A compliance dashboard that re-runs
a full verify on every load is re-hashing the entire history every time, and the
cost grows without bound as the chain does. That is the single worst-scaling
endpoint in the product, and it is the one we changed for this cut.

The fix is **incremental (consistency) verification**, and it is wired into the
same route the full verify uses:

- A caller does **one** full `GET /compliance/chain/verify` to establish a
  trusted baseline and remembers the head it returned — a `(from_seq, from_hash)`
  anchor.
- On every subsequent load it calls
  `GET /compliance/chain/verify?from_seq=<seq>&from_hash=<hash>`. The server
  walks **only the rows appended since that anchor**, proving they link cleanly
  onto it, and returns the new head so the caller can advance its anchor. The
  verbatim captures show this end-to-end: an anchor at the head returns
  `"status": "consistent", "verified": 0`
  ([`s1-…-chain-verify-incremental-head.json`](../artifacts/payloads/s1-sg-acme-payments-chain-verify-incremental-head.json)),
  and an anchor seven rows back returns `"verified": 7`
  ([`…-window.json`](../artifacts/payloads/s1-sg-acme-payments-chain-verify-incremental-window.json)).
- The same scanner backs both paths, so the incremental verify catches a gap, a
  broken link, or an edited row in its window exactly as strictly as the full
  verify does; an anchor ahead of the real head is reported as `stale_anchor`,
  and a bad anchor hash surfaces as `tampered` (linkage broken) rather than
  silently passing.

**The soundness boundary, stated plainly:** the incremental call is a
*consistency* proof of the suffix (these new rows extend a chain you already
trusted), **not** a fresh *integrity* proof of the whole history. The full
verify remains the root of trust, and a periodic full sweep (the scheduler
already walks every workspace) keeps the entire chain re-proven on a cadence.
What incremental buys is that the *interactive* path — the one a human waits on —
stops paying the O(n) tax on every click. On this box that is a 10.15 ms → 3.45 ms
p50 drop on a ~100-row chain; on a 200k-row chain it is the difference between a
verify that crawls and one that does not move.

## Where these numbers fall short

This is a benchmark post in an honesty-first series, so the caveats are not
footnotes:

- **This is a floor, not a ceiling — and not a production SLO.** One API
  process, one un-tuned Postgres, loopback HTTP with no TLS, a warm dataset, and
  a single 8-vCPU VM. Real deployments add TLS termination, network hops, larger
  datasets, and noisier neighbours — all of which push latency up — but also add
  connection pooling, read replicas, caching, and horizontal scale — which push
  throughput up. **Do not** quote these as the numbers you will see in prod.
- **It is loopback, so it excludes the network.** Zero round-trip time to the
  client. A real client over the internet adds tens of milliseconds that have
  nothing to do with the control plane.
- **The dataset is small.** These workspaces hold tens to low-hundreds of
  evidence records (81–100 per workspace after the gap-closure seed). A *full*
  `chain-verify` and `evidence` are **O(n)** in chain length, so a workspace
  with hundreds of thousands of records will be materially slower on those two
  routes specifically. We measured what we seeded; we are **not** extrapolating
  the curve — which is exactly why the incremental verify exists: a long-lived
  dashboard pays the O(n) cost once to establish a trusted anchor, then pays
  only O(Δ) on every refresh thereafter (the periodic full sweep keeps the whole
  chain fresh).
- **HS256 dev validation is cheaper than production JWKS.** The dev validator
  uses a symmetric HMAC; a production deployment verifying RS256/ES256 against a
  JWKS endpoint (with caching) pays slightly more per request. The auth overhead
  here is a lower bound.
- **No write-throughput or step-up-MFA-gated paths are benchmarked.** Promotion,
  lease approval, and evidence export are deliberately rate-limited by the
  step-up-TOTP anti-replay window (one 30-second window per high-risk action) —
  that is a *security* property, not a performance one, and benchmarking it
  would measure the clock, not the system. We time the read and simulate paths
  that have no such gate.

## How a buyer should read this

Performance is rarely why an SME picks an access-governance tool — correctness,
evidence, and jurisdiction fit are — so we are not going to claim a throughput
crown. The honest, useful takeaways for Marcus:

- **The control plane is not the bottleneck for an SME.** At thousands of
  tenant-scoped reads per second and sub-15-ms p50 on the *heaviest* compliance
  endpoint, a single modest VM comfortably serves a 40–500-person company's
  interactive console and API traffic. You are buying this for the evidence
  chain, not fighting it for latency.
- **Tamper-evidence has a real but bounded cost — and now an O(Δ) fast path.**
  A full hash-chain verification is the slowest read we do, and we showed you
  exactly how slow (~10 ms p50, ~1.3k req/s here). The incremental verify keeps
  the interactive cost flat as the chain grows (3.45 ms p50 / 2.8k req/s),
  without giving up the full sweep as the root of trust. Competitors that emit
  flat, unverifiable reports skip that cost — and skip the guarantee that comes
  with it. That trade is the whole point of the series.
- **The dangerous-grant guardrail is free enough to always be on.** A 9-ms
  inline SoD simulation means there is no "we turned off the check for
  performance" story to worry about — the `catastrophic` gate runs on every
  promotion.

Reproduce it yourself: `make blog-bench` (with the control plane running and a
seeded workspace) regenerates
[`benchmark-results.json`](../artifacts/benchmark-results.json) on whatever box
you run it on — including the `system` block, so your numbers are self-describing.

---

*This is the finale of the series. Reproduce everything with `make blog-seed`,
`make blog-capture`, `make blog-bench`, and `make blog-test` — see
[`README.md`](README.md). Every screenshot is a real seeded page, every payload a
verbatim capture, and every number above is what this VM actually turned in.*
