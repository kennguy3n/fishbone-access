# How to build this, part 2: the data model

The data model *is* the product. Everything else — the API, the gateway, the UI —
is a way of reading and appending to a small set of tables that have to satisfy
three hard constraints at once: **multi-tenant isolation that cannot be bypassed
by a bug**, **an evidence trail that cannot be forged or silently edited**, and
**a per-tenant cost low enough for 5,000 SMEs**. This post is the schema and the
reasoning.

All of it is real, in [`internal/migrations`](../../internal/migrations) (31
idempotent SQL migrations) and [`internal/models`](../../internal/models) (GORM
models). File paths are exact.

## Tenancy: one `workspace_id`, everywhere

The root of the model is `workspaces`. Almost every other table carries a
`workspace_id UUID NOT NULL REFERENCES workspaces(id)`, and almost every query is
scoped by it. A workspace *is* a tenant: its policies, connectors, targets,
leases, sessions, evidence, agents, and discovered assets all hang off it.

This is the most important and least glamorous decision in the system.

### Decision: pooled multi-tenancy with a hard isolation backstop

**The fork.** Three classic options: database-per-tenant, schema-per-tenant, or
**pooled** (one schema, `workspace_id` column, shared tables).

**What we chose.** Pooled — *plus* Postgres Row-Level Security as a backstop.

**Why, at 5,000 tenants.** Database-per-tenant is the safest isolation and the
most operationally expensive: 5,000 databases to migrate, back up, monitor, and
connection-pool is an ops team's full-time job — exactly the headcount our buyer
doesn't have. Pooled is the only model whose *operational* cost stays flat as
tenants grow. The well-known risk of pooled is the isolation bug: one missing
`WHERE workspace_id =` leaks across tenants. So we don't rely on discipline
alone.

### RLS as the thing that catches the bug you didn't catch

[`0024_row_level_security.sql`](../../internal/migrations/0024_row_level_security.sql)
enables RLS on every tenant-scoped table and adds a policy keyed on a
session-local setting:

```sql
CREATE FUNCTION app_current_workspace_id() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('app.workspace_id', true), '')::uuid $$;

-- for each tenant table: USING (workspace_id = app_current_workspace_id())
```

The middleware sets `app.workspace_id` for the connection once the tenant is
resolved. After that, **Postgres itself refuses to return another tenant's
rows** — even if a service forgets to scope a query, even if a hand-written
report has a bug. The application scoping is the primary control (it's faster and
clearer); RLS is the seatbelt. We would rather pay a tiny per-query cost than
ever explain a cross-tenant leak.

## The evidence chain: the table that makes the product trustworthy

Compliance tools emit reports. The problem with a report is that it is just a
selection of the truth at a point in time, with nothing stopping someone editing
the record behind it. Our answer is `audit_events`
([`0001_init.sql`](../../internal/migrations/0001_init.sql)):

```sql
CREATE TABLE audit_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    actor        TEXT,
    action       TEXT NOT NULL,
    target_ref   TEXT,
    metadata     JSONB,
    prev_hash    TEXT,         -- chain_hash of the previous row in this workspace
    chain_hash   TEXT NOT NULL,-- this row's link
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Every consequential action — a policy promote, a grant, a lease approval, a
rotation, an onboard — appends one row. The linkage is a per-workspace hash
chain. From
[`internal/services/compliance/evidence.go`](../../internal/services/compliance/evidence.go),
each row's link is:

```
chain_hash = SHA256( prev_hash || workspace || action || target || metadata || ts_micros )
```

with a strictly-increasing per-workspace `chain_seq`. Verification re-walks the
chain and checks two invariants: **linkage** (each row's `prev_hash` equals the
prior row's `chain_hash`, the first row's `prev_hash` is empty, and `chain_seq` is
contiguous) and **content** (each row's `chain_hash` recomputes from its fields).
Tamper with any row — edit a field, delete a row, reorder — and the recomputed
hash diverges from the next row's `prev_hash`, and verification fails at exactly
that link.

### Decision: hash-chain in Postgres, not a blockchain, not "just a log"

**The fork.** Tamper-evidence has a spectrum: a plain append-only log (trust the
DB admin), a hash chain (detect any edit), an external notary / blockchain
(detect even a colluding admin).

**What we chose.** A per-workspace hash chain *in the same Postgres*, with an
optional periodic full re-verify as the root of trust.

**Why.** A plain log doesn't survive the question "could an admin have edited
this?" — which is the question an auditor actually asks. A blockchain survives a
colluding-admin threat model that our SME buyer does not have and would pay
dearly (in cost and complexity) to defend against. The hash chain is the
**right point on the curve**: it makes silent edits detectable with a cost of one
SHA-256 per append, no external dependency, and no new infrastructure to run.
That last clause is the SME lens again — a notary service is one more thing to
operate.

### The scaling trap we designed around: O(n) verify

A full verify recomputes *every* link, so it is **O(n)** in chain length. For a
tenant accreting evidence for years, a dashboard that re-verifies on every load
re-hashes the entire history every time. That is the single worst-scaling read
in the product (Post 7 measures it). The fix is **incremental consistency
verification**: `GET /compliance/chain/verify?from_seq=&from_hash=` re-checks only
the rows appended since an anchor the caller already trusts — **O(Δ)**. The
interactive path pays O(n) once to establish an anchor, then O(Δ) forever; a
scheduled full sweep remains the root of trust. The honest boundary, stated in
the code and the showcase: incremental is a *consistency* proof of the suffix,
not a fresh *integrity* proof of the whole history.

## Per-workspace encryption keys

Connector secrets, PAM credentials, and sealed TOTP secrets are encrypted at
rest. The key is **derived per workspace**: with a KMS master key set,
[`internal/services/access/derived_key_manager.go`](../../internal/services/access/derived_key_manager.go)
uses HKDF to derive a distinct DEK per `workspace_id`; the encryptor
(`credential_encryptor.go`) forwards `workspace_id` so envelope encryption always
resolves the right key.

### Decision: a key *per tenant*, derived not stored

**Why.** A single shared DEK means one key compromise exposes every tenant's
secrets — unacceptable at 5,000 tenants. Storing 5,000 independent keys is its
own management burden. **Derivation** (one master key → per-tenant DEK via HKDF)
gives cryptographic isolation between tenants with nothing extra to store: the
per-tenant key exists only when needed and is reproducible from the master key
and the `workspace_id`. Rotating the master rotates everyone; compromise of one
tenant's derived key doesn't generalise.

## The access graph, table by table

The rest of the model is the access graph. Grouped by subsystem (each gets its
own post):

| Subsystem | Key tables | Migration |
| --- | --- | --- |
| Connectors | `access_connectors`, `access_sync_state` | 0001–0003 |
| Lifecycle / JML | `access_requests`, `access_grants`, `access_jobs`, JML runs | 0004, 0014 |
| Policy / SoD | policies, `sod_rules`, `access_anomalies` | 0020, 0021 |
| Certifications | `certification_campaigns`, `certification_items` | 0017 |
| Contractor access | `contractor_grants`, `contractor_grant_extensions` | 0022, 0023 |
| PAM core | `pam_targets`, `pam_leases`, `pam_connect_tokens`, `pam_sessions`, `pam_session_commands` | 0005, 0016 |
| Outbound agents | `agents`, `agent_enrollment_tokens`, `agent_reachable_targets` | 0030 |
| Rotation | `rotation_policies`, `rotation_events`, dynamic credentials | 0050–0052 |
| Recordings | `session_recordings` (+ FTS), retention policies | 0060–0062 |
| Discovery | `discovered_assets`, `discovered_accounts`, auto-onboarding policy | 0070 |
| Agent HA | `agent_session_directory` | 0080 |

Two modelling conventions repeat and are worth copying:

- **Soft deletes (`deleted_at`) with partial unique indexes.** Uniqueness is
  enforced `WHERE deleted_at IS NULL`, so a name can be reused after a soft
  delete without losing the historical row — which matters because the evidence
  chain references things that no longer exist.
- **Status enums as `TEXT` with explicit transitions, not booleans.** An agent is
  `enrolled / online / offline / revoked`; a discovered asset is
  `unmanaged / managed`; a rotation policy mode is `disabled / interval / checkin`.
  Booleans can't represent "revoked vs merely offline," and the distinction is
  exactly what an auditor asks about.

### Decision: migrations are embedded and idempotent

The migration runner embeds the SQL and every statement is `IF NOT EXISTS` /
guarded, so the same migration can run against a fresh DB or a half-applied one
without manual intervention. For a no-ops product this is non-negotiable: an
upgrade must be a deploy, never a DBA runbook.

---

*Next: [Post 10 — building the connector fabric](10-building-the-connector-fabric.md).*
