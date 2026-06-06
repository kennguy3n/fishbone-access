// Package access defines the AccessConnector contract implemented by every
// external system ShieldNet Access syncs identities with, provisions access
// against, federates SSO with (via iam-core Connections — never Keycloak), or
// pulls audit events from.
//
// Connector implementations live under
// internal/services/access/connectors/<provider>/ and register themselves with
// the process-global registry (factory.go) from an init() side effect. The
// running binary blank-imports the consolidated connectors/all package so every
// provider's init() runs.
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
	// IdentityTypeGroup is a group / team / role aggregate of users.
	IdentityTypeGroup IdentityType = "group"
	// IdentityTypeServiceAccount is a non-human, machine-to-machine identity.
	IdentityTypeServiceAccount IdentityType = "service_account"
)

// Sentinel errors returned by AccessConnector implementations and the registry.
var (
	// ErrDeltaTokenExpired signals the provider rejected the supplied delta
	// link (e.g. Microsoft Graph 410 Gone). Callers clear the stored
	// deltaLink and fall back to a full enumeration.
	ErrDeltaTokenExpired = errors.New("access: delta token expired")

	// ErrConnectorNotFound is returned by GetAccessConnector when no init()
	// side-effect registered the requested provider key — almost always a
	// missing blank-import in the running binary. Handlers map this to 503.
	ErrConnectorNotFound = errors.New("access: connector not registered for provider")

	// ErrCapabilityNotSupported is returned when a requested capability is
	// structurally absent from the upstream provider (e.g. a breach-lookup
	// API has no identity model). Distinct from "not yet implemented".
	// Handlers map this to 422.
	ErrCapabilityNotSupported = errors.New("access: capability not supported by provider")

	// ErrNotImplemented is returned by connectors for a capability that is
	// planned but not yet built. Distinct from ErrCapabilityNotSupported.
	ErrNotImplemented = errors.New("access: capability not implemented")

	// ErrAuditNotAvailable is returned by AccessAuditor implementations when
	// the connected tenant/plan does not expose an audit-log API. Callers
	// treat this as a soft-skip rather than a hard error.
	ErrAuditNotAvailable = errors.New("access: audit logs not available for this tenant")
)

// AccessConnector is the contract every provider package implements. The
// config/secrets maps are the connector's decrypted configuration and
// credentials; secrets are sealed with AES-GCM at rest and only opened
// immediately before a call.
type AccessConnector interface {
	// Validate checks the configuration and secrets are well-formed.
	// Implementations MUST NOT perform network I/O.
	Validate(ctx context.Context, config map[string]any, secrets map[string]any) error

	// Connect verifies credentials against the provider. Network I/O.
	Connect(ctx context.Context, config map[string]any, secrets map[string]any) error

	// VerifyPermissions checks the connector has the requested capabilities
	// and returns those that are missing or unauthorized.
	VerifyPermissions(ctx context.Context, config map[string]any, secrets map[string]any, capabilities []string) (missing []string, err error)

	// CountIdentities returns the expected full-sync identity count. Best-effort.
	CountIdentities(ctx context.Context, config map[string]any, secrets map[string]any) (int, error)

	// SyncIdentities streams identity pages via handler. checkpoint is the
	// opaque pagination cursor; an empty next-page cursor terminates the sync.
	// Implementations that yield no rows MUST pass a non-nil empty slice so
	// downstream JSON marshals to [] not null.
	SyncIdentities(ctx context.Context, config map[string]any, secrets map[string]any, checkpoint string, handler func(batch []*Identity, nextCheckpoint string) error) error

	// ProvisionAccess pushes a grant to the provider. Idempotent on
	// (grant.UserExternalID, grant.ResourceExternalID).
	ProvisionAccess(ctx context.Context, config map[string]any, secrets map[string]any, grant AccessGrant) error

	// RevokeAccess revokes a grant on the provider. Idempotent.
	RevokeAccess(ctx context.Context, config map[string]any, secrets map[string]any, grant AccessGrant) error

	// ListEntitlements returns the live entitlement set for one user.
	ListEntitlements(ctx context.Context, config map[string]any, secrets map[string]any, userExternalID string) ([]Entitlement, error)

	// GetSSOMetadata returns the federation metadata iam-core needs to broker
	// SAML/OIDC for this provider (used to create an iam-core Connection).
	GetSSOMetadata(ctx context.Context, config map[string]any, secrets map[string]any) (*SSOMetadata, error)

	// GetCredentialsMetadata returns expiry/scope/fingerprint data WITHOUT
	// decrypting the cached secret. Drives expiry alerts and the renewal cron.
	GetCredentialsMetadata(ctx context.Context, config map[string]any, secrets map[string]any) (*CredentialsMetadata, error)
}

// Identity is one user/group/service-account record from a provider.
type Identity struct {
	ExternalID  string         `json:"external_id"`
	Type        IdentityType   `json:"type"`
	DisplayName string         `json:"display_name"`
	Email       string         `json:"email"`
	ManagerID   string         `json:"manager_id,omitempty"`
	Status      string         `json:"status"`
	GroupIDs    []string       `json:"group_ids,omitempty"`
	RawData     map[string]any `json:"raw_data,omitempty"`
}

// AccessGrant is the grant pushed to / revoked from a provider.
type AccessGrant struct {
	UserExternalID     string         `json:"user_external_id"`
	ResourceExternalID string         `json:"resource_external_id"`
	Role               string         `json:"role"`
	Scope              map[string]any `json:"scope,omitempty"`
	GrantedAt          time.Time      `json:"granted_at"`
	ExpiresAt          *time.Time     `json:"expires_at,omitempty"`
}

// Entitlement is one live entitlement returned by ListEntitlements.
type Entitlement struct {
	ResourceExternalID string     `json:"resource_external_id"`
	Role               string     `json:"role"`
	Source             string     `json:"source"`
	LastUsedAt         *time.Time `json:"last_used_at,omitempty"`
	RiskScore          *int       `json:"risk_score,omitempty"`
}

// SSOMetadata is the federation metadata used to configure an iam-core
// Connection for this provider.
type SSOMetadata struct {
	// Protocol is "saml" or "oidc".
	Protocol string `json:"protocol"`
	// MetadataURL is the OIDC discovery document or SAML metadata XML URL.
	MetadataURL string `json:"metadata_url"`
	// EntityID / Issuer is the provider's stable identifier.
	EntityID string `json:"entity_id,omitempty"`
	// SSOLoginURL is the redirect target for SP-initiated login.
	SSOLoginURL string `json:"sso_login_url,omitempty"`
	// SSOLogoutURL is the redirect target for single logout.
	SSOLogoutURL string `json:"sso_logout_url,omitempty"`
	// SigningCertificates are PEM-encoded x509 certs (SAML only).
	SigningCertificates []string `json:"signing_certificates,omitempty"`
	// IAMCoreStrategy is the iam-core Connection catalog slug this provider
	// maps to (e.g. "microsoft", "google-oauth2", "oidc" for Okta).
	IAMCoreStrategy string `json:"iam_core_strategy,omitempty"`
}

// CredentialsMetadata describes stored credentials without revealing them.
type CredentialsMetadata struct {
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Scopes         []string   `json:"scopes,omitempty"`
	KeyFingerprint string     `json:"key_fingerprint,omitempty"`
}
