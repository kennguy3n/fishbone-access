package access

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

// ErrSSOFederationDisabled is returned when ConfigureSSO is called on a service
// built without a ConnectionConfigurator. Callers treat this as a soft-fail:
// connector setup proceeds, SSO federation is reported as unconfigured.
var ErrSSOFederationDisabled = errors.New("access: sso federation not configured (no iam-core connection client)")

// ErrSSOFederationUnsupported is returned when a connector's GetSSOMetadata
// returns (nil, nil) — the connector does not federate SSO. This is a normal
// control-flow signal, not a failure: callers MUST NOT surface it as an error.
var ErrSSOFederationUnsupported = errors.New("access: connector does not advertise SSO metadata")

// ErrSSOStrategyUnknown is returned when no iam-core connection strategy can be
// resolved for a provider — neither an explicit mapping nor a usable
// SSOMetadata.Protocol (oidc/saml). Fail closed rather than guessing a slug.
var ErrSSOStrategyUnknown = errors.New("access: no iam-core connection strategy for provider")

// strategyByProvider maps connector provider keys to iam-core connection
// strategy slugs (docs/iam-core-integration.md §3). Providers absent from this
// table fall back to a generic slug derived from the connector's SSOMetadata
// protocol. This replaces every Keycloak IdP-broker mapping inherited from the
// reference platform — SSO federation is an iam-core Connection, not a Keycloak
// identity provider.
var strategyByProvider = map[string]string{
	"microsoft":        "microsoft", // Entra ID / Azure AD
	"azure":            "microsoft", // Azure AD alias
	"google_workspace": "google-oauth2",
	"okta":             "oidc", // generic OIDC
	"auth0":            "oidc",
	"ping_identity":    "oidc",
	"github":           "github",
	"zoho_crm":         "zoho",
}

// ConnectionConfigurator is the narrow slice of the iam-core Management client
// the SSO federation service needs. iamcore.ManagementClient satisfies it; unit
// tests inject a fake so no live iam-core is required.
type ConnectionConfigurator interface {
	CreateConnection(ctx context.Context, conn iamcore.Connection) (*iamcore.Connection, error)
	DeleteConnection(ctx context.Context, id string) error
	TestConnection(ctx context.Context, id string) error
	ToggleConnection(ctx context.Context, id string, enabled bool) error
}

// SSOFederationService configures customer IdP single sign-on by creating an
// iam-core Connection (POST /api/v1/management/connections) from a connector's
// advertised SSOMetadata. It is a thin orchestration layer: it resolves the
// strategy slug, projects metadata onto connection options, and delegates the
// API call. iam-core owns the connection lifecycle and any secrets it stores.
type SSOFederationService struct {
	connections ConnectionConfigurator
}

// NewSSOFederationService wires the service to a ConnectionConfigurator. A nil
// configurator is allowed (processes that disable SSO federation): ConfigureSSO
// then short-circuits with ErrSSOFederationDisabled.
func NewSSOFederationService(connections ConnectionConfigurator) *SSOFederationService {
	return &SSOFederationService{connections: connections}
}

// ConfigureSSOInput is the payload for ConfigureSSO.
type ConfigureSSOInput struct {
	WorkspaceID uuid.UUID
	Provider    string
	DisplayName string
	Connector   AccessConnector
	Config      map[string]interface{}
	Secrets     map[string]interface{}
}

// ConfigureSSO reads the connector's SSO metadata and creates the corresponding
// iam-core Connection. It returns ErrSSOFederationUnsupported (a soft signal)
// when the connector does not federate SSO, and ErrSSOFederationDisabled when
// the service has no connection client.
func (s *SSOFederationService) ConfigureSSO(ctx context.Context, in ConfigureSSOInput) (*iamcore.Connection, error) {
	if s == nil || s.connections == nil {
		return nil, ErrSSOFederationDisabled
	}
	if in.Connector == nil {
		return nil, fmt.Errorf("access: ConfigureSSO: connector is nil")
	}
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("access: ConfigureSSO: workspaceID required")
	}

	meta, err := in.Connector.GetSSOMetadata(ctx, in.Config, in.Secrets)
	if err != nil {
		return nil, fmt.Errorf("access: ConfigureSSO: get sso metadata: %w", err)
	}
	if meta == nil {
		return nil, ErrSSOFederationUnsupported
	}

	strategy, err := resolveStrategy(in.Provider, meta)
	if err != nil {
		return nil, err
	}

	conn := iamcore.Connection{
		Name:     connectionName(in.WorkspaceID, in.Provider),
		Strategy: strategy,
		Options:  connectionOptions(meta, in.Secrets),
		Enabled:  true,
	}
	created, err := s.connections.CreateConnection(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("access: ConfigureSSO: create iam-core connection: %w", err)
	}
	return created, nil
}

// RemoveSSO deletes a previously-created iam-core Connection by id.
func (s *SSOFederationService) RemoveSSO(ctx context.Context, connectionID string) error {
	if s == nil || s.connections == nil {
		return ErrSSOFederationDisabled
	}
	if connectionID == "" {
		return fmt.Errorf("access: RemoveSSO: connectionID required")
	}
	return s.connections.DeleteConnection(ctx, connectionID)
}

// resolveStrategy picks the iam-core strategy slug for a provider. Explicit
// per-provider mappings win; otherwise it falls back to the connector's
// advertised protocol (oidc/saml), both of which are generic catalog slugs.
func resolveStrategy(provider string, meta *SSOMetadata) (string, error) {
	if slug, ok := strategyByProvider[provider]; ok {
		return slug, nil
	}
	switch strings.ToLower(strings.TrimSpace(meta.Protocol)) {
	case "oidc":
		return "oidc", nil
	case "saml":
		return "saml", nil
	default:
		return "", fmt.Errorf("%w: %q (protocol %q)", ErrSSOStrategyUnknown, provider, meta.Protocol)
	}
}

// connectionName builds a stable, workspace-scoped connection name so two
// tenants federating the same provider never collide in iam-core.
func connectionName(workspaceID uuid.UUID, provider string) string {
	return fmt.Sprintf("shieldnet-%s-%s", provider, workspaceID.String())
}

// connectionOptions projects connector SSOMetadata (and any client credentials
// the connector surfaced in secrets) onto the iam-core connection options bag.
// Only non-empty fields are included so we never send empty strings iam-core
// would have to special-case.
func connectionOptions(meta *SSOMetadata, secrets map[string]interface{}) map[string]any {
	opts := map[string]any{}
	if meta.MetadataURL != "" {
		// iam-core uses discovery_url for OIDC and metadata_url for SAML; send
		// both keys pointed at the same well-known document so the strategy
		// handler can pick whichever it needs.
		opts["discovery_url"] = meta.MetadataURL
		opts["metadata_url"] = meta.MetadataURL
	}
	if meta.EntityID != "" {
		opts["entity_id"] = meta.EntityID
	}
	if meta.SSOLoginURL != "" {
		opts["sso_login_url"] = meta.SSOLoginURL
	}
	if meta.SSOLogoutURL != "" {
		opts["sso_logout_url"] = meta.SSOLogoutURL
	}
	if len(meta.SigningCertificates) > 0 {
		opts["signing_certificates"] = meta.SigningCertificates
	}
	// OIDC connections need the registered client credentials. Connectors that
	// federate OIDC surface these under conventional secret keys.
	if v, ok := stringSecret(secrets, "sso_client_id"); ok {
		opts["client_id"] = v
	}
	if v, ok := stringSecret(secrets, "sso_client_secret"); ok {
		opts["client_secret"] = v
	}
	return opts
}

// stringSecret reads a string value from the secrets map, returning ok=false
// when the key is absent or not a non-empty string.
func stringSecret(secrets map[string]interface{}, key string) (string, bool) {
	if secrets == nil {
		return "", false
	}
	v, ok := secrets[key].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
