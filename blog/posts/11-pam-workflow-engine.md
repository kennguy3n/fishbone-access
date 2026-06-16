# How to build this, part 4: the PAM workflow engine

This is the deepest subsystem in the product: privileged access to SSH boxes and
databases, governed end to end — request → approval → time-boxed lease → recorded
session → searchable, replayable, chain-anchored evidence — plus credential
rotation so the standing secret an attacker wants to steal keeps changing. This
post is how that engine is wired.

The code spans
[`internal/services/pam`](../../internal/services/pam) (leases, rotation),
[`internal/gateway`](../../internal/gateway) (the multi-protocol proxy), and
[`internal/services/recordings`](../../internal/services/recordings) (the
searchable index). Migrations 0005, 0016, 0050–0052, 0060–0062.

## The lease is the unit of privilege

A privileged target (`pam_targets`) is never connected to directly. Access is a
**lease** (`pam_leases`), and its lifecycle is:

```
requested ──▶ approved ──▶ active ──▶ expired
     │            │           │
     └────────────┴───────────┴──▶ revoked  (any time)
```

The crucial implementation detail: from
[`0016_pam_leases.sql`](../../internal/migrations/0016_pam_leases.sql), **state is
DERIVED from a timestamp tuple** `(granted_at, activated_at, expires_at,
revoked_at)`, not stored as a mutable `status` column. A connect-token broker
turns the lease `active` the moment a session opens against it; expiry is a fact
about `expires_at < now()`, not a flag someone has to flip.

### Decision: derive state from timestamps, don't store a status

**Why.** A stored `status` column is a lie waiting to happen — it can disagree
with reality if a transition is missed (a process dies between "expire the lease"
and "write status='expired'"). Deriving status from immutable timestamps means
the lease *cannot* be in a state its timestamps don't justify: an expired lease
is expired because the clock says so, even if no sweep has run yet. Partial
indexes on the `granted-but-not-revoked` set keep the reconciler's sweep cheap as
the table grows. This is the same philosophy as the audit chain: **make the data
structurally unable to misrepresent the truth.**

## Connect tokens: one-shot, short-lived, never the real credential

The operator never receives the target's real credential. When a session opens,
the broker mints a **connect token** (`pam_connect_tokens`): one-shot,
short-lived (`expires_at`), stored only as a hash. The operator's client presents
the token to the gateway; the gateway resolves it, opens the upstream with the
*real* sealed credential (decrypted per-workspace at use), and the token is
spent.

### Decision: a broker token, not credential hand-off

**Why, for an SME.** The alternative — checking out the real password to a human —
is how credentials leak into shell history, tickets, and chat. A one-shot token
that the human never sees means the credential's blast radius is the gateway
process, not the operator's laptop. It also makes the *ephemeral* path (below)
natural: if the credential only ever lives inside the gateway for the life of a
session, it can just as easily be a credential that was minted for that session
and destroyed after.

## The gateway: a recording, policy-enforcing proxy

`cmd/pam-gateway` is an in-path proxy for each protocol (SSH, PostgreSQL, MySQL,
MongoDB, k8s-exec, …). For every session it:

1. Resolves the connect token → lease → target, and **fails closed** if the lease
   isn't active or the policy denies the command.
2. Splices operator ↔ upstream bytes through an `IORecorder`
   (`NewIORecorder(sessCtx, session.ID, recMaxBytes)` — see
   `internal/gateway/*_handler.go`), capturing the real wire bytes.
3. Enforces **command policy** inline (denied commands are blocked and recorded
   as denied), and applies **step-up MFA** on high-risk sessions.
4. Anchors session open/close on the workspace **audit hash chain** via the
   session manager, so the recording's existence and integrity are part of the
   evidence (Post 9).

Because every protocol handler funnels through the same recorder + session
manager, recording and chaining are not per-protocol features that can drift —
they are the spine every handler is built on.

### Decision: in-path proxy with byte capture, not agent-side logging

**Why, vs the residual we own.** Capturing bytes *in the path* means the recording
is the ground truth of what crossed the wire, not a self-report from a box we
don't control. The honest residual (stated in the showcase) is that our demo
upstream is a bastion, so we prove the *pipeline* — capture → index → replay →
re-verify — end to end, not live keystrokes off a production host. Pointed at a
reachable upstream, the same `IORecorder` captures real production bytes; the
architecture doesn't change, only the target does. CyberArk's session vault is
heavier here and owns live-keystroke capture at scale; we trade some of that for
"runs itself, and the recording is anchored on the same chain as the policy that
authorised it."

## Searchable recording + in-browser replay

A recording you can only fetch by id is an archive, not a forensic tool. Every
closed session is projected into `session_recordings` with a **full-text index**
([`0061_session_recordings_fts.sql`](../../internal/migrations/0061_session_recordings_fts.sql))
over the commands the operator ran (plus facets: operator, protocol, target,
time). An auditor searches by *what was done*, gets matching sessions, and opens
the in-browser player: time-ordered transcript, synchronized command timeline
(denied commands highlighted), and a **live tamper-evidence badge** that
re-verifies the recording's SHA-256 against the chain at view time.

The index is a **DB-only projection by design**: it indexes from durable facts
(`pam_session_commands`, the anchored digest) even if the blob store is
unreachable, and indexing failures are fail-open (logged, non-fatal) because the
session is already closed and anchored — the index is a convenience, not the root
of trust.

## Credential rotation: the standing secret keeps moving

Standing secrets are what attackers actually steal, so the engine
([`rotation_engine.go`](../../internal/services/pam/rotation_engine.go)) rotates
them three ways:

- **interval** — on a schedule;
- **rotate-on-checkin** — after each session;
- **rotate-now** — on demand.

Each goes through a real executor (`PostgresExecutor` → `ALTER ROLE`,
`MySQLExecutor` → `ALTER USER`, `SSHExecutor` → key rotation) that **verifies by
reconnecting** with the new credential and **rolls back** if verification fails
(`rotation_executor.go`). The new secret is re-sealed under the workspace DEK and
the rotation is written to the audit chain **in the same transaction**. It can
also mint **ephemeral per-lease database credentials** that exist only for the
life of a session.

### Decision: verify-by-reconnect with rollback, not fire-and-forget

**Why.** A rotation that "succeeds" by issuing an `ALTER` but never confirms the
new credential works is how you lock yourself out of a production database — the
single scariest failure for a no-ops customer. Reconnecting with the new
credential before committing means a failed rotation **leaves the upstream
untouched** (there's a regression test for exactly this:
`TestRotationEngine_RotateFailureLeavesUpstreamUntouched`). The rotation either
fully works and is provable, or it didn't happen. For a customer with no DBA on
call, "rotation can never lock me out" is worth more than rotation that is
slightly faster.

The scheduler is on the workflow engine and **hibernation-gated**: idle tenants
aren't rotated on a timer they're not using.

---

*Next: [Post 12 — discovery and governed onboarding](12-discovery-and-onboarding.md).*
