# How to build this, part 5: discovery and governed onboarding

You cannot govern what you don't know exists. The gap between "the access tool
the SME bought" and "every privileged account and asset they actually have" is
where breaches live. This post is how fishbone-access closes that gap — three
real discovery sources, a reconcile step, and an **opt-in auto-onboard that never
grants standing access**.

The code is in
[`internal/services/discovery`](../../internal/services/discovery); the schema is
[`0070_discovery.sql`](../../internal/migrations/0070_discovery.sql).

## Three sources, one inventory

Discovery is not a network scanner bolted on the side. It reuses substrate the
product already has, three ways:

1. **Agent reachable-import** (`agent_reachable.go`). The same outbound connector
   agent that reaches a private subnet (Post 13) *self-reports what it can see*:
   its reachable CIDR and host:port bindings. The engine imports those as
   candidate assets and infers the protocol per port (`5432 → postgres`,
   `3306 → mysql`, `22 → ssh`). No new agent, no scanning appliance — the reach we
   already have becomes an inventory.
2. **Connector inventory** (`connector_inventory.go`). Through a connector's
   *sealed* credentials, the engine reads cloud inventory — AWS EC2 + RDS, Azure
   VMs + SQL — so discovery isn't limited to what one agent can ping.
3. **Database account enumeration** (`discovered_accounts`). For managed database
   targets it enumerates `pg_roles` / `mysql.user`, flagging accounts that can log
   in, superusers, and logins that exist on the box but aren't governed —
   **orphans**.

All three land in two tables:

```sql
discovered_assets   (workspace_id, source, external_id, protocol, address,
                     status,            -- 'unmanaged' | 'managed'
                     agent_id, connector_id, target_id,  -- provenance + linkage
                     policy_matched, first_seen_at, last_seen_at)

discovered_accounts (workspace_id, target_id, username, source,
                     status, can_login, superuser, attributes, ...)
```

### Decision: reuse reach + sealed creds, don't build a scanner

**The fork.** The obvious way to discover assets is an active network scanner.

**What we chose.** Derive the inventory from things we already operate — the
agent's reach and the connector's credentials — rather than shipping a scanner.

**Why, through the SME lens.** A scanner is one more privileged thing to deploy,
secure, and explain to a customer who has no security team — and active scanning
of a customer's network is exactly the kind of action that triggers their IDS and
their lawyer. Reusing the agent's *already-authorised* reach and the connector's
*already-sealed* credentials means discovery inherits the trust boundary the
customer already granted. Nothing new is deployed, and we never touch a host the
customer didn't already connect us to.

## Reconcile: managed vs unmanaged vs orphan

Discovered assets are reconciled against the PAM targets already under
management. The identity key is `(workspace_id, source, external_id)` with a
partial unique index, so re-running discovery is **idempotent** — the same asset
seen twice updates `last_seen_at`, it doesn't duplicate. An asset already backed
by a `pam_target` is `managed`; everything else is `unmanaged` and surfaced for a
decision. An account that can log in but maps to no governed identity is an
**orphan** — the highest-signal finding, because it's standing access nobody is
watching.

In the seeded demo, one workspace's edge agent surfaces **5 assets — 1 managed**
(the ledger bastion) **and 4 unmanaged** (a Postgres primary, a reporting MySQL,
a build host, a private subnet range) it had never inventoried.

## Onboarding: turn "exists" into "governed", never "open"

Onboarding a discovered asset (`onboard.go`,
`OnboardAsset(ctx, workspaceID, assetID, in)`) goes through the **real PAM vault
path** — RBAC, step-up MFA, audit chain — and creates a managed `pam_target`. It
claims the asset first (`claimAssetForOnboard`) so two operators can't onboard the
same asset into two targets.

The safety boundary is the entire point:

> **Auto-onboard creates the managed target. It never creates standing access.**

The optional auto-onboarding policy (`policy.go`, `SavePolicy`) is **opt-in** and
scoped by source and protocol (e.g. "SSH bastions seen by the agent sweep"). When
it fires it creates the target with **`require_lease` pinned server-side**, so
every session against a freshly-onboarded asset *still* flows request → approve →
time-boxed lease (Post 11). Auto-onboard changes "an asset is invisible" to "an
asset is under governance" — it does not, ever, change it to "an asset is open."

### Decision: auto-onboard is opt-in, and lease-pinned, by construction

**The fork.** Auto-onboarding is a convenience-vs-safety dial. Crank it toward
convenience and discovery could *grant access* to whatever it finds. Crank it
toward safety and every asset needs a human click.

**What we chose.** The dial only goes as far as "create the governed target
automatically." Granting *access* always requires the lease flow, and that is
pinned in the server, not the UI — a misconfigured client can't bypass it.

**Why.** The whole pitch to an SME is "we make you safer without a security
team." An auto-onboarding feature that could silently grant standing access would
do the opposite: it would manufacture exactly the unwatched standing access we
exist to eliminate. So the feature is deliberately *less* powerful than it could
be. It removes the toil (finding and registering assets) and keeps the human
decision where it belongs (granting access). CyberArk has deep account discovery;
where we differ is insisting that discovery's output is *governed* by the same
JIT lease as everything else, with no standing-access shortcut.

## The sweep is scheduled, gated, and cheap

Discovery runs on the workflow engine (`scheduler.go`, `RunScheduledSweep`),
**hibernation-gated** like every other sweep, with the `(workspace, status,
last_seen)` index keeping "show me what's unmanaged" a cheap read. An idle tenant
isn't scanned on a timer; an active one keeps its inventory fresh without anyone
running anything.

---

*Next: [Post 13 — cross-replica HA for the agent plane](13-cross-replica-ha.md).*
