# How to build this, part 6: cross-replica HA for the agent plane

This is the subtlest problem in the system, and the one most directly shaped by
the "no-ops SME at 5,000 tenants" constraint. The outbound connector agent
(Post 1, Post 8) is what lets us reach a customer's private network with zero
inbound exposure. But that agent's tunnel terminates on **one** server replica —
and in a horizontally-scaled deployment, a privileged session can land on a
*different* replica. This post is how we make the agent plane highly available
without asking the customer to run anything, and without a sticky load balancer.

The code is in [`internal/broker`](../../internal/broker); the schema is
[`0080_agent_session_directory.sql`](../../internal/migrations/0080_agent_session_directory.sql).

## The problem, precisely

`cmd/pam-gateway` runs as multiple replicas behind a load balancer. An outbound
agent dials *out* over mTLS and its tunnel (a yamux multiplexed session) lives
**only in the memory of the one replica it connected to**. Now an operator opens
a privileged session that needs `DialThroughAgent`. The load balancer routes that
request to whichever replica is free — which may be a *different* replica, one
that has no local tunnel for that agent. Before this subsystem, that session
**failed closed** even though the agent was online and healthy *elsewhere*.

The naive fixes are all bad for our buyer:

- **Sticky sessions** (pin an agent's traffic to its replica at the LB): now the
  customer — or we — operate a stateful load balancer, and a replica restart
  drops every agent pinned to it.
- **Broadcast/fan-out** ("ask every replica if it owns this agent"): O(replicas)
  chatter on every dial, and a thundering-herd problem at scale.
- **A shared in-memory mesh**: a new distributed system to operate, which is the
  opposite of no-ops.

## The design: a durable directory + epoch-CAS ownership + an mTLS forward plane

The answer is a single authoritative table that records **which replica owns each
agent's live tunnel**, so any replica can *forward* a dial to the owner instead of
failing closed.

```sql
CREATE TABLE agent_session_directory (
    workspace_id       UUID NOT NULL REFERENCES workspaces(id),
    agent_id           UUID NOT NULL REFERENCES agents(id),
    owner_node_id      TEXT NOT NULL,   -- which replica
    owner_forward_addr TEXT NOT NULL,   -- internal replica-to-replica mTLS addr
    epoch              BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, agent_id)
);
```

The ownership protocol (single-writer per `(workspace_id, agent_id)`):

- the owning replica **claims** the row when an agent registers, **bumping
  epoch**;
- it **refreshes** `last_seen_at` on heartbeat — *coalesced*, never per-dial;
- it **clears** the row on disconnect (hard delete — a fast-reconnecting agent
  must not accumulate tombstones);
- a reconnect (possibly to another replica) **takes over by bumping epoch**, and
  every refresh/release is conditioned on the claimant still holding *that exact
  epoch* — a **compare-and-set**. A stale owner whose tunnel already died cannot
  clobber or delete a newer owner's claim.

A dial on a non-owning replica looks up the owner by `(workspace, agent)` (the
primary key serves it) and forwards over a **separate mTLS inter-replica plane**
(`forward_tls.go`) with its own internal CA — distinct from the public listener,
never exposed to tenants. If the owner is unreachable, the dial **fails closed**.

### Decision: a Postgres directory, not a sticky LB or a new cluster

**Why epoch-CAS specifically.** The hard case in any ownership scheme is the
*stale owner*: replica A owned the agent, A's tunnel died, the agent reconnected
to B — and now A wakes up and tries to refresh or release "its" row. A naive
last-writer-wins directory lets A clobber B and re-break the very session B is
serving. Conditioning every write on the epoch the writer claimed means A's write
is rejected the instant B bumps the epoch: ownership transfer is atomic and a
zombie owner is harmless. This is the same "make the data structurally unable to
misrepresent the truth" principle as the derived lease state (Post 11) and the
hash chain (Post 9).

**Why this fits 5,000 tenants.** Read the cost discipline baked into the schema
comments: **at most one row per *online* agent; empty and dormant workspaces
store nothing**; `last_seen_at` is refreshed on heartbeat, coalesced, **never per
dial — so 5,000 dormant tenants add zero write traffic**. The directory is
effectively free for the 90% of tenants that are idle at any moment, and O(1) per
active agent for the rest. There is no new datastore: it's a table in the
Postgres we already run, enrolled into the **same RLS** policy as everything else
(Post 9), so a cross-tenant forwarded dial is non-exploitable even if an
application-level filter were ever forgotten.

## Derived health, not a stored "online" flag

Whether an agent is usable is **derived**, not stored
([`directory.go`](../../internal/broker/directory.go)): an agent is `online` only
if its status is online **and** its last heartbeat is within
`HealthOfflineAfter = 90 * time.Second`. A stored "online" boolean would lie the
moment a replica died without cleaning up; deriving health from heartbeat recency
means a silently-dead agent reads `offline` after 90 seconds with no sweep
required. (This is exactly why the screenshot harness emits a fresh heartbeat
before capture — it's standing in for the real agent's heartbeat signal so the
console renders the true `online` state, not a stale one.)

## What the customer experiences

Nothing. That is the goal. A rolling deploy or a replica restart does not drop
privileged access: the agent reconnects to some replica, claims the directory row
with a new epoch, and dials forwarded from anywhere keep working. There is no
sticky load balancer to configure, no cluster membership to operate, no
customer-side change. Teleport and StrongDM achieve HA too — by running a cluster
(Teleport) or a managed service (StrongDM). We achieved it with **one table, an
epoch counter, and an internal mTLS hop**, so the no-ops promise survives contact
with horizontal scale.

### The honest residual

The forward plane adds one internal network hop to a dial that lands on a
non-owning replica — a few milliseconds, and only on the cross-replica path
(same-replica dials are direct). The single audit-open and the revoke re-check
still happen **at the owner**, so tenant scoping and the audit trail are never
weakened by the hop; the cost is latency, not correctness. An optional Redis
fast-path can shortcut the owner lookup, but the Postgres directory remains the
source of truth — we don't trade the durability guarantee for the cache.

---

*This closes the build-along sub-series. Start at
[Post 8 — architecture overview](08-architecture-overview.md), or go back to
[the showcase](00-series-intro.md) to see all of this running over real seeded
data.*
