package access

import (
	"context"
	"time"
)

// IdentityDeltaSyncer is implemented by connectors that can stream incremental
// identity changes (Microsoft Graph delta query, Okta event hooks, Auth0
// log-stream, ...).
//
// Semantics mirror the SN360 EmployeeDeltaSyncer pattern:
//
//   - The handler is invoked once per provider page.
//   - removedExternalIDs lets the caller tombstone identities directly without
//     a separate enumeration pass.
//   - The very last page sets a non-empty finalDeltaLink and an empty nextLink.
//     Callers persist finalDeltaLink in access_sync_state and feed it back on
//     the next sync.
//   - When the provider rejects the supplied deltaLink (HTTP 410 Gone for
//     Microsoft Graph, expired token for Okta) implementations MUST return
//     ErrDeltaTokenExpired so the service drops the stored link and falls
//     back to a full enumeration.
//
// InitialDeltaCursor returns a connector-specific opaque cursor that, when
// passed to SyncIdentitiesDelta on the very next call, yields "events from
// approximately now onwards." The orchestrator invokes it once after a
// successful full SyncIdentities so the next run can enter the delta path
// without re-enumerating the entire identity population. Implementations are
// expected to be cheap — most return `time.Now().UTC().Format(time.RFC3339Nano)`
// without any network call. Providers whose cursor shape requires a baseline
// fetch (e.g. Microsoft Graph @odata.deltaLink, Auth0 log_id token) may
// perform exactly one minimal-bandwidth API call (use `$select=id&$top=1` or
// equivalent). Returning an empty cursor with no error tells the orchestrator
// to skip the seeding step and remain in full-sync mode on the next run —
// reserve that for explicit "this connector cannot synthesise a baseline
// cursor" cases. Any non-nil error fails the orchestrator's post-full-sync
// cursor seeding, which is logged but does NOT mark the full sync as failed.
type IdentityDeltaSyncer interface {
	SyncIdentitiesDelta(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		deltaLink string,
		handler func(batch []*Identity, removedExternalIDs []string, nextLink string) error,
	) (finalDeltaLink string, err error)

	InitialDeltaCursor(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (cursor string, err error)
}

// GroupSyncer is implemented by connectors that expose groups / teams as a
// first-class entity separate from users (Microsoft 365 unified groups, Google
// Workspace groups, Okta groups, ...).
//
// Empty-batch contract (applies to SyncGroups and SyncGroupMembers):
// implementations that need to invoke the handler with no rows — e.g.
// "group exists but currently empty" or "group was deleted mid-pagination
// and the leaver-flow contract requires a terminal call" — MUST pass a
// non-nil empty slice (`[]*Identity{}` or `[]string{}`), NOT a nil slice.
// Rationale:
//
//   - Downstream consumers that JSON-marshal the batch directly into an
//     audit-log envelope, a webhook payload, or a checkpoint state
//     document see `[]` instead of `null`. `null` requires every
//     consumer to special-case the field; `[]` is uniformly safe.
//   - Within Go, `len(nil)`, `range nil`, and `append(nil, ...)` all
//     work identically to an empty slice, so the typed-empty form
//     never breaks existing callers.
//   - The receiving handler can tell the difference between "the
//     connector is signalling end-of-stream with no rows" (non-nil
//     empty slice + empty nextCheckpoint) and "the connector forgot
//     to initialise the batch" (nil slice). The latter is treated as
//     a defensive bug indicator.
//
// SyncIdentities (in types.go) is governed by the same contract.
type GroupSyncer interface {
	CountGroups(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (int, error)

	SyncGroups(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		checkpoint string,
		handler func(batch []*Identity, nextCheckpoint string) error,
	) error

	SyncGroupMembers(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		groupExternalID string,
		checkpoint string,
		handler func(memberExternalIDs []string, nextCheckpoint string) error,
	) error
}

// DefaultAuditPartition is the partition key single-endpoint connectors
// (and the legacy single-cursor contract) emit when they call the
// AccessAuditor handler.
const DefaultAuditPartition = ""

// AccessAuditor is implemented by connectors that can stream sign-in / access
// audit events back into the audit pipeline.
//
// Semantics:
//
//   - `sincePartitions` maps a partition key to its persisted cursor.
//     A connector MUST look up its own partition keys and treat a
//     missing entry as a zero-time "full backfill" (provider default
//     window). Single-endpoint connectors look up
//     `sincePartitions[DefaultAuditPartition]`. Multi-endpoint
//     connectors (e.g. Microsoft Graph `signIns` and `directoryAudits`)
//     look up their per-endpoint keys.
//   - The handler is invoked once per provider page. Implementations MUST
//     paginate the provider's audit log API and call the handler per page
//     in chronological order so callers can persist `nextSince` as a
//     monotonic cursor.
//   - `nextSince` is the per-partition cursor the caller should persist
//     for `partitionKey` so the next invocation resumes where this one
//     left off. Implementations MUST set nextSince to the timestamp of
//     the newest entry in the batch (or beyond).
//   - `partitionKey` identifies the audit stream the batch came from.
//     Single-endpoint connectors MUST use DefaultAuditPartition.
//     Multi-endpoint connectors MUST use a stable, distinct key per
//     endpoint so the worker can advance each partition's cursor
//     independently. This prevents a fast-moving partition's max
//     timestamp from shadowing a slower partition's progress and causing
//     `$filter ge {inflated}` to skip events on retry after a partial
//     failure.
//   - Implementations MUST honour ctx cancellation between pages.
//   - The handler returning a non-nil error aborts the sync.
type AccessAuditor interface {
	FetchAccessAuditLogs(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		sincePartitions map[string]time.Time,
		handler func(batch []*AuditLogEntry, nextSince time.Time, partitionKey string) error,
	) error
}

// SCIMProvisioner is implemented by connectors that support outbound SCIM v2.0
// push for joiner / mover / leaver flows.
type SCIMProvisioner interface {
	PushSCIMUser(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		user SCIMUser,
	) error

	PushSCIMGroup(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		group SCIMGroup,
	) error

	DeleteSCIMResource(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		resourceType string,
		externalID string,
	) error
}

// SSOEnforcementChecker is implemented by SaaS connectors that can
// answer "is password / non-SSO login disabled on this tenant?".
// (docs/architecture.md §13) uses the check at connector
// setup time, on the connector-health endpoint, and on the daily
// orphan-account reconciler so an SSO-only connector that silently
// regresses (e.g. an admin re-enables basic auth) surfaces in the
// admin UI without waiting for a leaver flow to discover it.
//
// Semantics:
//
//   - enforced=true means "every interactive login goes through
//     the federated IdP". The connector implementation decides
//     what counts as enforcement: Okta sign-on policy rules, Slack
//     team.info SSO enforcement, GitHub org SAML, etc.
//   - enforced=false means "at least one non-SSO login path is
//     reachable". The details string carries a short human-readable
//     hint (e.g. "password login still allowed for 3 users").
//   - A nil error with enforced=false is the canonical "regression"
//     signal — callers MUST NOT confuse it with a transient
//     connector outage.
//   - A non-nil error means the check itself could not complete
//     (network outage, permission denied). Callers surface this as
//     "unknown" enforcement state, never as "not enforced".
type SSOEnforcementChecker interface {
	CheckSSOEnforcement(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (enforced bool, details string, err error)
}

// SessionRevoker is implemented by SaaS connectors that can sign
// a user out of every active session on the tenant.
// (docs/architecture.md §13) calls this from the leaver flow as one
// of the six layers of the kill switch — terminating long-lived
// SaaS sessions matters even after the IdP itself has been
// disabled, because many SaaS apps re-validate IdP only on session
// expiry (which can be 30+ days).
//
// Semantics:
//
//   - userExternalID is the SaaS-native identifier (Okta user ID,
//     Google primaryEmail, GitHub login, etc.) — the same value
//     the connector emits during SyncIdentities.
//   - Implementations are best-effort: a non-nil error is logged
//     by the leaver flow and surfaces in the audit trail, but it
//     does NOT block the rest of the leaver chain. The user's
//     access is already revoked at the policy layer; session
//     termination is belt-and-braces.
//   - A successful return means the revoke request was accepted
//     by the upstream API. Some providers (Okta, Google) revoke
//     synchronously; others (Slack, Microsoft) acknowledge and
//     propagate within minutes. Implementations document the
//     specific semantics in their package comments.
type SessionRevoker interface {
	RevokeUserSessions(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		userExternalID string,
	) error
}

// CredentialRenewer is implemented by connectors that can renew their
// own credentials autonomously — e.g. OAuth2 connectors that hold a
// long-lived refresh_token and can mint a fresh access_token, AWS
// connectors that can call STS AssumeRole to get a new time-bound
// credential, time-bound API keys behind a vendor rotation endpoint.
//
// The cron in
// internal/services/access/connector_credential_renewer.go scans
// access_connectors rows whose CredentialExpiredTime is inside a
// configurable look-ahead window (ACCESS_CONNECTOR_CREDENTIAL_RENEWAL_WINDOW,
// 24h default), type-asserts each provider against this interface,
// and calls RenewCredentials on the ones that opt in. The new
// secrets blob is re-validated via AccessConnector.Validate +
// Connect before being persisted under the latest DEK and the row's
// CredentialExpiredTime is bumped to newExpiresAt.
//
// Implementations:
//
//   - MUST be side-effect free against the gateway DB — they ONLY
//     talk to the upstream provider. The persistence write is
//     done by the cron after a successful renewal so the DB and
//     the upstream provider never disagree on which credential is
//     active.
//   - SHOULD return newSecrets as a fully self-contained map that
//     replaces the existing secrets blob. OAuth providers typically
//     rotate the refresh_token on every refresh; the new value MUST
//     be carried back in newSecrets or the next renewal will fail
//     with an expired-grant error from the provider.
//   - SHOULD return newExpiresAt as the *upstream-reported* expiry
//     (e.g. `expires_in` seconds added to now). For short-TTL
//     credentials (AWS STS 15-min tokens, OAuth access tokens
//     with `expires_in: 3600`) the implementation MUST return
//     the real expiry — passing this back faithfully is what
//     keeps the renewal cron correctly scheduled for the next
//     pass.
//   - When the upstream does not return an expiry at all (rare —
//     non-standard providers), implementations MUST return a
//     zero time.Time AND a nil error. The cron treats this as
//     "renewed but expiry unknown" and writes
//     CredentialExpiredTime = now + ACCESS_CONNECTOR_CREDENTIAL_RENEWAL_WINDOW
//     so the row stays in the renewal cron's scope and gets
//     re-attempted on the next window boundary rather than the
//     immediate next tick (which would cause a tight retry loop).
//     Implementations MUST NOT synthesise a fake far-future
//     expiry — return zero and let the cron own the fallback
//     scheduling.
//   - SHOULD return ErrCredentialsNotRenewable when the connector
//     type registers as a CredentialRenewer but THIS specific
//     row's secrets do not carry the renewal material (e.g. a
//     Microsoft Entra connector configured with a static client
//     secret instead of a refresh-token grant). The cron logs
//     this as "skipped" rather than "failed" so the operator can
//     decide whether to migrate the row's auth flow.
//   - MUST NOT panic on a zero secrets map — return
//     ErrCredentialsNotRenewable in that case so the cron skips
//     instead of crashing the worker goroutine.
type CredentialRenewer interface {
	RenewCredentials(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (newSecrets map[string]interface{}, newExpiresAt time.Time, err error)
}
