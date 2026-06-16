# How to build this, part 3: the connector fabric

A connected system is where access *actually* lives — the Okta tenant, the AWS
account, the GitHub org, the database. An access-governance product is only as
useful as the breadth of systems it can read and act on. fishbone-access ships a
catalogue of 200+ connectors, and they all share one code path. This post is how
that fabric is built so that adding the 201st provider is a small, well-shaped
job rather than a fork of the whole engine.

The code is in
[`internal/services/access`](../../internal/services/access) — the
`AccessConnector` interface in
[`types.go`](../../internal/services/access/types.go), the optional capabilities
in
[`optional_interfaces.go`](../../internal/services/access/optional_interfaces.go),
and one directory per provider under
[`connectors/`](../../internal/services/access/connectors).

## One required interface, narrow on purpose

Every connector implements `AccessConnector`. The contract is deliberately small:

```go
type AccessConnector interface {
    // Validate checks config/secrets are well-formed. MUST NOT do network I/O.
    Validate(ctx, config, secrets) error
    // Connect verifies credentials. Network I/O allowed.
    Connect(ctx, config, secrets) error
    // VerifyPermissions checks requested capabilities, returns the missing ones.
    VerifyPermissions(ctx, config, secrets, capabilities) (missing []string, err error)
    // CountIdentities: best-effort total for a full sync.
    CountIdentities(ctx, config, secrets) (int, error)
    // SyncIdentities streams identity pages through a handler (cursor pagination).
    SyncIdentities(ctx, config, secrets, checkpoint, handler) error
}
```

That is the whole required surface: **validate, connect, verify, count, sync**.
A new connector that can only *read* who has access (the common case) implements
exactly this and nothing else.

### Decision: capabilities are *optional interfaces*, not a giant interface or flags

**The fork.** Connectors vary wildly — some can provision via SCIM, some can
revoke sessions, some can enforce SSO, most can only read. How do you model that
variation? Three usual answers: one fat interface with `NotSupported` stubs
everywhere; a bag of boolean capability flags; or **optional interfaces** that a
connector implements only if it truly supports the capability.

**What we chose.** Optional interfaces. Beyond the required `AccessConnector`, a
provider may *also* implement any of:

| Optional interface | Capability |
| --- | --- |
| `IdentityDeltaSyncer` | incremental (delta) identity sync, not just full |
| `GroupSyncer` | enumerate groups/roles, not just users |
| `SCIMProvisioner` | create/update/deprovision accounts downstream |
| `SessionRevoker` | kill active sessions (the leaver kill switch) |
| `SSOEnforcementChecker` | assert SSO is enforced for the tenant |
| `AccessAuditor` | emit provider-side audit facts |
| `CredentialRenewer` | renew its own credentials before expiry |

The engine does a type assertion at the point of use: `if r, ok := conn.(SessionRevoker); ok { r.RevokeSessions(...) }`. If the assertion fails, the
capability simply isn't offered for that provider — no stub, no flag to keep in
sync with reality.

**Why this matters for the product.** The capability a connector advertises is
*exactly* the capability it has, enforced by the compiler. There is no way to
claim "supports deprovisioning" in a config flag while the method is a stub —
the leaver kill switch (a safety-critical path) can only call connectors that
genuinely implement `SessionRevoker`. The registry even has count tests
(`registry_count_test.go`) that fail if the number of, say, `SessionRevoker`
implementations changes unexpectedly, so capability drift is caught in CI.

## The empty-batch contract: a small rule that prevents a class of bug

Notice the long comment on `SyncIdentities`: an implementation that has zero rows
to report must pass a **non-nil empty slice** (`[]*Identity{}`), never `nil`.
This is the same nil-vs-empty discipline that bit the recordings search in the
showcase (serializing `null` instead of `[]` crashed a UI). Encoding it as a
written contract on the interface — and locking the SSO-only "no enumeration"
variant in per-connector flow tests — means every one of 200+ connectors handles
the empty case the same way. **At fabric scale, conventions you can't enforce
are conventions you don't have.**

## How a connector is built (the wired steps)

To add a provider, end to end:

1. **Create the directory** `connectors/<provider>/` with a `connector.go`
   implementing `AccessConnector`. Network I/O lives in `Connect`/`SyncIdentities`
   only; `Validate` stays pure so config can be checked without a live system.
2. **Implement the optional interfaces it genuinely supports** (e.g. add
   `SCIMProvisioner` if it can deprovision). Don't stub the ones it can't.
3. **Register it** so it appears in the catalogue with a capability descriptor
   (`capability_descriptor.go`) describing the config/secret schema the setup UI
   renders.
4. **Lock its behaviour in a flow test** — including its empty-batch and
   "no enumeration" choices — so the contract is observable, not assumed.
5. The registry count tests update; the connector is now usable by sync,
   provisioning, the kill switch, and discovery (Post 12 reads cloud inventory
   through the same connectors' sealed credentials).

## Secrets never travel in the clear

Connector secrets (`config` is plaintext, `secrets` is sensitive) are sealed with
the **per-workspace derived key** from Post 9 before they touch the database, via
the `credential_encryptor`. The connector code receives decrypted secrets only at
the moment of use, scoped to one workspace. If the DEK is unavailable, secret
persistence **fails closed** — we never store a secret we can't seal.

### Decision: breadth via a thin contract, depth where it pays

**The honest position.** 200+ connectors *register*; not all 200 implement deep
provisioning. The breadth is real (the catalogue and its schemas exist and are
exercised), but the per-provider depth is a deliberate prioritisation: the
providers an SME actually connects (their IdP, cloud, code host, databases) get
the deep capabilities first; the long tail starts as read/sync and earns
provisioning when demand shows up.

**Why, vs the incumbents.** SailPoint and Saviynt win on the *number* of deeply
integrated enterprise systems — that is decades of integration work for
customers who connect dozens of niche systems. Our buyer connects a handful of
mainstream systems and needs them to *just work* on day one. So we optimise for
"the systems an SME has, integrated deeply and safely" over "every system any
enterprise might have, integrated shallowly." A thin required interface plus
optional capabilities is what lets us hold both truths: broad catalogue, deep
where it counts, with the compiler keeping us honest about which is which.

## Background, not blocking

Sync and provisioning run on the **worker** (`access-connector-worker`), not in
the request path: a full identity sync of a large IdP can't block an API call,
and a leaver kill switch must complete even if the admin closes their laptop.
Jobs are durable and **hibernation-gated** — an idle tenant's connectors aren't
polled, which is a real slice of the per-tenant cost saving at 5,000 tenants.

---

*Next: [Post 11 — the PAM workflow engine](11-pam-workflow-engine.md).*
