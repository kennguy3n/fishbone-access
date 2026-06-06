package access

import "context"

// The interfaces below are OPTIONAL capabilities. A connector advertises a
// capability simply by implementing the corresponding interface; callers
// type-assert on the AccessConnector value to discover support at runtime. This
// keeps the mandatory AccessConnector surface small while letting rich
// providers (Entra, Okta, Google Workspace, ...) expose delta sync, group sync,
// audit ingestion, SCIM provisioning, session revocation, and SSO enforcement.

// IdentityDeltaSyncer is implemented by connectors that support incremental
// (change-feed) sync. delta is the opaque cursor persisted between runs. A
// provider that rejects an expired cursor returns ErrDeltaTokenExpired so the
// caller falls back to a full SyncIdentities.
type IdentityDeltaSyncer interface {
	SyncIdentitiesDelta(ctx context.Context, config map[string]any, secrets map[string]any, delta string, handler func(batch []*Identity, nextDelta string) error) error
}

// GroupSyncer is implemented by connectors that enumerate group membership
// separately from user records. Implementations yielding no rows MUST pass a
// non-nil empty slice.
type GroupSyncer interface {
	SyncGroups(ctx context.Context, config map[string]any, secrets map[string]any, checkpoint string, handler func(batch []*Group, nextCheckpoint string) error) error
}

// Group is a group/role record with its members.
type Group struct {
	ExternalID  string   `json:"external_id"`
	DisplayName string   `json:"display_name"`
	MemberIDs   []string `json:"member_ids,omitempty"`
}

// AccessAuditor is implemented by connectors that expose an audit-log API. It
// returns ErrAuditNotAvailable (a soft-skip) when the tenant/plan lacks the
// audit surface.
type AccessAuditor interface {
	FetchAuditEvents(ctx context.Context, config map[string]any, secrets map[string]any, since string, handler func(batch []*ProviderAuditEvent, nextCursor string) error) error
}

// ProviderAuditEvent is one normalized audit record from a provider.
type ProviderAuditEvent struct {
	ExternalID string         `json:"external_id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	Target     string         `json:"target,omitempty"`
	OccurredAt string         `json:"occurred_at"`
	RawData    map[string]any `json:"raw_data,omitempty"`
}

// SCIMProvisioner is implemented by connectors that provision via SCIM 2.0
// rather than a bespoke REST API.
type SCIMProvisioner interface {
	SCIMBaseURL(config map[string]any) (string, error)
}

// SessionRevoker is implemented by connectors that can terminate a user's
// active provider sessions (part of the leaver kill switch).
type SessionRevoker interface {
	RevokeSessions(ctx context.Context, config map[string]any, secrets map[string]any, userExternalID string) error
}

// SSOEnforcementChecker is implemented by connectors that can report whether
// SSO is enforced for the tenant (so the platform can flag local-password
// bypass risk).
type SSOEnforcementChecker interface {
	IsSSOEnforced(ctx context.Context, config map[string]any, secrets map[string]any) (bool, error)
}
