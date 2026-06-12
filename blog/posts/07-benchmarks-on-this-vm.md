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
a degraded endpoint cannot look fast by dropping its slow samples.

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
| liveness | `GET /health` | 0.56 | 1.85 | 2.85 | 0.81 | 18,974 |
| catalogue | `GET /connectors/providers` (200+) | 0.83 | 2.08 | 4.14 | 1.01 | 15,501 |
| catalogue | `GET /connectors/catalogue/facets` | 1.67 | 2.69 | 4.14 | 1.78 | 8,776 |
| govern | `GET /packs?region=sg` | 1.53 | 2.59 | 5.01 | 1.71 | 9,224 |
| govern | `GET /policies` | 4.44 | 22.18 | 37.69 | 7.39 | 2,124 |
| lifecycle | `GET /access-requests` | 5.18 | 24.59 | 39.71 | 8.60 | 1,766 |
| lifecycle | `GET /connectors` | 9.29 | 23.87 | 39.21 | 11.87 | 1,329 |
| pam | `GET /pam/targets` | 4.70 | 21.26 | 35.55 | 7.65 | 2,014 |
| pam | `GET /pam/leases` | 4.34 | 22.23 | 36.03 | 7.20 | 2,084 |
| compliance | `GET /compliance/coverage?framework=SOC 2` | 9.77 | 29.55 | 46.37 | 13.39 | 1,157 |
| compliance | `GET /compliance/chain/verify` | 11.22 | 30.56 | 45.06 | 14.38 | 1,075 |
| compliance | `GET /compliance/evidence` | 11.34 | 32.51 | 57.66 | 15.41 | 1,005 |
| engine | `POST /policies/simulate-definition` | 9.13 | 34.11 | 52.93 | 13.78 | 1,122 |

## Reading the shape

The numbers tell a coherent story, and the *ordering* is the interesting part —
it tracks how much work each route actually does:

- **Static / in-memory reads are effectively free.** `/health` and the 200+
  provider catalogue answer in **sub-millisecond p50** and push **15k–19k
  req/s** on one box. The connector catalogue is served from memory, so breadth
  (201 providers) costs almost nothing to read.
- **Tenant-scoped DB reads sit in the low single-digit-millisecond p50** and a
  few thousand req/s. `/policies`, `/access-requests`, `/pam/targets`, and
  `/pam/leases` all land around **4–5 ms p50**, with p99 pulled up to the
  20–40 ms range by Postgres round-trips under concurrency — normal for an
  untuned single instance.
- **Compliance is the heaviest read, *by design*.** `chain-verify` (11 ms p50)
  recomputes the SHA-256 link for **every** record in the workspace chain, and
  `evidence/coverage` walks and projects the chain onto a framework. They are
  the slowest endpoints in the set, and that is the *correct* cost: it is the
  price of tamper-evidence and one-chain-many-maps that the rest of the series
  sells. Even so, the box serves **~1,000–1,160 verifications/second**.
- **The policy/SoD engine is cheap enough to run inline.** A full dry-run
  simulation — impact analysis **plus** the toxic-combination check — costs
  **9 ms p50 / 14 ms mean**. That matters: it means the `catastrophic`
  guardrail in Posts 1, 3 and 5 is not an expensive batch job, it is fast enough
  to run synchronously on every promote.

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
  evidence records. `chain-verify` and `evidence` are **O(n)** in chain length,
  so a workspace with hundreds of thousands of records will be materially
  slower on those two routes specifically. We measured what we seeded; we are
  not extrapolating the curve.
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
- **Tamper-evidence has a real but bounded cost.** Hash-chain verification is
  the slowest thing we do, and we showed you exactly how slow (11 ms p50, ~1.1k
  req/s here). Competitors that emit flat, unverifiable reports skip that cost —
  and skip the guarantee that comes with it. That trade is the whole point of
  the series.
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
