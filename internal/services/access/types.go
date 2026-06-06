// Package access defines the AccessConnector contract used by every external
// system the ShieldNet 360 Access Platform syncs identities with, provisions
// access against, federates SSO with, or pulls audit events from.
//
// The contract intentionally mirrors the SN360 Connector pattern (see
// shieldnet360-backend/internal/services/connectors/types.go) and layers
// access-specific methods on top. Implementations live under
// internal/services/access/connectors/<provider>/ and register themselves via
// init() side-effects against the process-global registry in factory.go.
package access

import (
	"context"
	"errors"
	"time"
)

// IdentityType enumerates the identity record kinds returned by SyncIdentities.
type IdentityType string

const (
	// IdentityTypeUser is a human user account.
	IdentityTypeUser IdentityType = "user"
	// IdentityTypeGroup is a group / team / role-style aggregate of users.
	IdentityTypeGroup IdentityType = "group"
	// IdentityTypeServiceAccount is a non-human, machine-to-machine identity.
	IdentityTypeServiceAccount IdentityType = "service_account"
)

// Sentinel errors returned by AccessConnector implementations and the registry.
var (
	// ErrDeltaTokenExpired signals that the provider rejected the supplied
	// deltaLink (e.g. Microsoft Graph returns HTTP 410 Gone, Okta returns
	// an expired event-hook token). Callers must clear the stored deltaLink
	// and fall back to a full enumeration.
	ErrDeltaTokenExpired = errors.New("access: delta token expired (provider rejected the supplied delta link)")

	// ErrConnectorNotFound is returned by GetAccessConnector when the
	// requested provider key is not registered. Process-global registry
	// hits this when a connector package was not blank-imported by the
	// running binary. Handlers map this onto HTTP 503 because a missing
	// blank-import is a deployment misconfiguration (the platform binary
	// is incomplete), not a missing user-facing resource.
	ErrConnectorNotFound = errors.New("access: connector not registered for provider")

	// ErrConnectorRowNotFound is returned by services that load a
	// specific access_connectors row by ID (Disconnect, RotateCredentials,
	// TriggerSync, provisioning lookups) when no row matches. This is
	// distinct from ErrConnectorNotFound — that one means the provider
	// implementation is missing from the binary; this one means the
	// row never existed or was already soft-deleted. Handlers map this
	// onto HTTP 404.
	ErrConnectorRowNotFound = errors.New("access: connector row not found by id")

	// ErrAuditNotAvailable is returned by AccessAuditor implementations
	// when the connected tenant/plan does not expose an audit log API
	// (e.g. Slack Audit Logs requires Enterprise Grid). Callers treat
	// this as a soft-skip rather than a hard error.
	ErrAuditNotAvailable = errors.New("access: audit logs not available for this tenant")

	// ErrCapabilityNotSupported is returned by connector implementations
	// when the requested capability is structurally absent from the
	// upstream provider — distinct from "not yet implemented" (caller
	// can retry once a future release lands) and from "not enabled on
	// this tenant" (caller can ask the customer to enable a feature
	// in the upstream).
	//
	// Examples of structurally-absent capabilities:
	//   - HIBP (Have I Been Pwned) has no user / group / SCIM model;
	//     it is a breach-lookup API only, so ProvisionAccess /
	//     SyncIdentities / GroupSync return ErrCapabilityNotSupported.
	//   - BitSight is an attack-surface / supply-chain rating service;
	//     it has no concept of "users in my tenant".
	//   - VirusTotal exposes a file-hash / URL-scan API; there is no
	//     identity model to provision against.
	//   - Wazuh is an agent-orchestration server; the only "identity"
	//     it has is its own admin token, not a directory of users.
	//
	// Handlers map this onto HTTP 422 with code "capability_not_supported".
	// The provisioning worker treats this as a clean skip (log + continue),
	// not a failure that would surface as ProvisionTaskFailed in the
	// task envelope. This is the correct long-term sentinel for the
	// "this connector cannot ever support this capability" class —
	// per-package ErrNotImplemented values used to overload this case
	// with "future capability not yet implemented", which made the
	// worker's audit log noisier than necessary.
	ErrCapabilityNotSupported = errors.New("access: capability not supported by this connector")

	// ErrCredentialsNotRenewable is returned by CredentialRenewer
	// implementations (internal/services/access/optional_interfaces.go)
	// when the connector type registers as a CredentialRenewer but a
	// SPECIFIC access_connectors row's secrets do not carry the
	// renewal material — e.g. a Microsoft Entra connector configured
	// with a static client_secret instead of a refresh-token grant,
	// or an AWS connector configured with long-lived access keys
	// instead of an STS-assumable role. The credential renewal cron
	// treats this as a SKIP (counted in Skipped, not Failed) rather
	// than a hard failure so a mixed fleet of renewable and
	// non-renewable rows of the same provider does not pollute the
	// failure rate. Operators looking at the structured summary log
	// line can decide on a per-row basis whether to migrate the row
	// to a renewable auth flow.
	ErrCredentialsNotRenewable = errors.New("access: credentials are not renewable for this connector configuration")
)

// AccessConnector is the mandatory contract every access provider implements.
//
// Method semantics (see docs/architecture.md §2 for the full table):
//
//   - Validate MUST NOT perform network I/O. It checks format, required
//     fields, and mutually-exclusive combinations only. Errors here surface
//     as 4xx during connector setup; nothing is persisted.
//   - Connect performs a network probe against the provider to verify
//     credentials. Errors abort the connect; nothing is persisted.
//   - VerifyPermissions probes the provider per requested capability and
//     returns the missing capability list (empty == fully permissioned).
//   - CountIdentities is a best-effort cheap header-only request when
//     possible. Errors are logged but do not fail downstream sync.
//   - SyncIdentities streams pages of Identity records via handler. The
//     handler returning a non-nil error aborts the sync. checkpoint is the
//     opaque pagination cursor — callers persist it across runs to resume.
//   - ProvisionAccess and RevokeAccess are one-shot RPC-style operations
//     that MUST be idempotent on (UserExternalID, ResourceExternalID).
//     4xx → permanent fail and surface to operator; 5xx → retry with
//     exponential backoff in the worker.
//   - ListEntitlements is best-effort during a campaign — per-user
//     failures do not fail the campaign.
//   - GetSSOMetadata returns the metadata iam-core needs to broker SSO. An
//     error here means SSO federation cannot be configured (user-visible).
//   - GetCredentialsMetadata returns optional expiry / scope / fingerprint
//     data without ever decrypting the cached secret. Drives expiry alerts
//     and the renewal cron.
type AccessConnector interface {
	// Validate checks if the configuration and secrets are well-formed.
	// Implementations MUST NOT perform network I/O.
	Validate(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}) error

	// Connect attempts a connection to verify credentials. Network I/O.
	Connect(ctx context.Context, config map[string]interface{}, secrets map[string]interface{}) error

	// VerifyPermissions checks the connector has the requested capabilities
	// and returns the list of capabilities that are missing or unauthorized.
	VerifyPermissions(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		capabilities []string,
	) (missing []string, err error)

	// CountIdentities returns the total count of identities the platform
	// expects to receive on a full sync. Best-effort.
	CountIdentities(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (int, error)

	// SyncIdentities streams identity pages via handler. checkpoint is the
	// opaque pagination cursor; the handler is invoked once per page with
	// the batch and the next-page cursor. An empty next-page cursor
	// terminates the sync.
	//
	// Empty-batch contract: implementations that need to invoke the
	// handler with no rows — e.g. "this connector is configured but the
	// platform has no identities", "audit-only connector that exposes
	// SyncIdentities as a no-op", or "this is the terminal page and the
	// last page was empty" — MUST pass a non-nil empty slice
	// (`[]*Identity{}`), NOT a nil slice. The rationale mirrors the
	// GroupSyncer empty-batch contract in optional_interfaces.go:
	// downstream consumers that JSON-marshal the batch into an audit
	// payload or checkpoint document see `[]` rather than `null`, and
	// the handler can distinguish "end-of-stream with no rows" from
	// "uninitialised batch (bug)".
	//
	// SSO-only / pure-federation variant: connectors whose platform has
	// no out-of-band identity enumeration surface at all — e.g. the
	// generic OIDC and generic SAML connectors where user records arrive
	// only through SSO sessions / assertions — MAY return nil WITHOUT
	// invoking the handler. This signals "no enumeration capability"
	// rather than "enumeration returned zero rows", which the orphan
	// reconciler and sync orchestrator both treat as a no-op (no
	// upserts, no tombstone-safety check). Connectors choosing this
	// variant SHOULD lock the behaviour in a test (cf.
	// generic_oidc/connector_flow_test.go and
	// generic_saml/connector_flow_test.go) so the choice is observable.
	SyncIdentities(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		checkpoint string,
		handler func(batch []*Identity, nextCheckpoint string) error,
	) error

	// ProvisionAccess pushes a grant out to the provider. Idempotent on
	// (grant.UserExternalID, grant.ResourceExternalID).
	ProvisionAccess(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		grant AccessGrant,
	) error

	// RevokeAccess revokes a grant on the provider. Idempotent.
	RevokeAccess(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		grant AccessGrant,
	) error

	// ListEntitlements returns the live entitlement set for a single user,
	// for use in periodic access check-ups.
	ListEntitlements(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
		userExternalID string,
	) ([]Entitlement, error)

	// GetSSOMetadata returns the federation metadata iam-core needs to
	// broker SAML / OIDC for this provider.
	GetSSOMetadata(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (*SSOMetadata, error)

	// GetCredentialsMetadata returns metadata about the credentials (expiry,
	// scope list, key fingerprint, ...) without decrypting the cached secret.
	GetCredentialsMetadata(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) (map[string]interface{}, error)
}

// Identity is the canonical record yielded by SyncIdentities. Provider-specific
// extras may be carried in RawData but production connectors should leave it
// nil unless a downstream consumer needs the raw payload.
type Identity struct {
	ExternalID  string                 `json:"external_id"`
	Type        IdentityType           `json:"type"`
	DisplayName string                 `json:"display_name"`
	Email       string                 `json:"email"`
	ManagerID   string                 `json:"manager_id,omitempty"`
	Status      string                 `json:"status"`
	GroupIDs    []string               `json:"group_ids,omitempty"`
	RawData     map[string]interface{} `json:"raw_data,omitempty"`
}

// AccessGrant describes a single (user, resource, role) grant for the
// ProvisionAccess / RevokeAccess methods. Scope carries provider-specific
// scoping (project IDs, region restrictions, etc.).
type AccessGrant struct {
	UserExternalID     string                 `json:"user_external_id"`
	ResourceExternalID string                 `json:"resource_external_id"`
	Role               string                 `json:"role"`
	Scope              map[string]interface{} `json:"scope,omitempty"`
	GrantedAt          time.Time              `json:"granted_at"`
	ExpiresAt          *time.Time             `json:"expires_at,omitempty"`
}

// Entitlement is one row of a user's effective access on a provider.
// RiskScore is populated downstream by the AI agent, never by the connector.
type Entitlement struct {
	ResourceExternalID string     `json:"resource_external_id"`
	Role               string     `json:"role"`
	Source             string     `json:"source"`
	LastUsedAt         *time.Time `json:"last_used_at,omitempty"`
	RiskScore          *int       `json:"risk_score,omitempty"`
}

// SSOMetadata is the subset of federation metadata iam-core needs to broker
// SAML or OIDC for this provider. Connectors that do not federate SSO return
// (nil, nil) from GetSSOMetadata.
type SSOMetadata struct {
	// Protocol is "saml" or "oidc".
	Protocol string `json:"protocol"`
	// MetadataURL is the well-known metadata endpoint (OIDC discovery
	// document or SAML metadata XML URL).
	MetadataURL string `json:"metadata_url"`
	// EntityID / Issuer is the provider's stable identifier.
	EntityID string `json:"entity_id,omitempty"`
	// SSOLoginURL is the redirect target for SP-initiated login.
	SSOLoginURL string `json:"sso_login_url,omitempty"`
	// SSOLogoutURL is the redirect target for single logout.
	SSOLogoutURL string `json:"sso_logout_url,omitempty"`
	// SigningCertificates is a list of PEM-encoded x509 certs the provider
	// uses to sign SAML responses; empty for OIDC providers.
	SigningCertificates []string `json:"signing_certificates,omitempty"`
}

// AuditLogEntry is one normalised access-related audit event yielded by the
// optional AccessAuditor capability. Event-shape stabilises across providers
// so the audit pipeline does not need provider-specific code paths.
//
// Canonical fields (per docs/architecture.md §2):
//
//   - EventType: provider event-type slug (e.g. "signIn", "role.assigned").
//   - ActorExternalID: identifier of the user / service-account who performed
//     the action, as known to the provider.
//   - TargetExternalID: identifier of the resource / user the action was
//     performed against, when applicable.
//   - Action: short verb describing the operation (e.g. "login", "grant",
//     "revoke"). Helps the audit pipeline classify events without parsing
//     EventType strings.
//   - Timestamp: when the event occurred at the provider.
//   - RawData: provider-specific extras for downstream investigations.
//
// Optional contextual fields (ActorEmail, IPAddress, UserAgent, Outcome,
// TargetType) are populated when the provider supplies them and dropped
// when not. They feed the audit-pipeline enrichment stages but are not
// required for correct downstream behaviour.
type AuditLogEntry struct {
	EventID          string                 `json:"event_id"`
	EventType        string                 `json:"event_type"`
	Action           string                 `json:"action,omitempty"`
	Timestamp        time.Time              `json:"timestamp"`
	ActorExternalID  string                 `json:"actor_external_id,omitempty"`
	ActorEmail       string                 `json:"actor_email,omitempty"`
	TargetExternalID string                 `json:"target_external_id,omitempty"`
	TargetType       string                 `json:"target_type,omitempty"`
	IPAddress        string                 `json:"ip_address,omitempty"`
	UserAgent        string                 `json:"user_agent,omitempty"`
	Outcome          string                 `json:"outcome,omitempty"`
	RawData          map[string]interface{} `json:"raw_data,omitempty"`
}

// SCIMUser is the minimal SCIM v2.0 user shape the SCIMProvisioner capability
// pushes to a provider. Extensions live in RawData.
type SCIMUser struct {
	ExternalID  string                 `json:"external_id"`
	UserName    string                 `json:"user_name"`
	DisplayName string                 `json:"display_name"`
	Email       string                 `json:"email"`
	Active      bool                   `json:"active"`
	GroupIDs    []string               `json:"group_ids,omitempty"`
	RawData     map[string]interface{} `json:"raw_data,omitempty"`
}

// SCIMGroup is the minimal SCIM v2.0 group shape the SCIMProvisioner capability
// pushes to a provider.
type SCIMGroup struct {
	ExternalID  string   `json:"external_id"`
	DisplayName string   `json:"display_name"`
	MemberIDs   []string `json:"member_ids,omitempty"`
}
