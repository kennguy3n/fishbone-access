package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/crypto"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// DBConnectorResolver is the production ConnectorResolver. It loads a connector
// row (workspace-scoped), decodes its JSON config, opens its AES-GCM sealed
// secret envelope, and looks up the registered AccessConnector implementation
// from the process-global registry.
//
// The secret envelope is bound to its connector id via AAD
// ("access_connector:" || connector_id), matching how the connector-management
// layer seals it: a ciphertext copied to another connector row fails to open.
type DBConnectorResolver struct {
	db  *gorm.DB
	enc crypto.Encryptor
	// lookup resolves a provider key to its implementation; defaults to the
	// process-global registry but is overridable in tests.
	lookup func(provider string) (access.AccessConnector, error)
}

// NewDBConnectorResolver wires the resolver to the DB and the credential
// encryptor (built from config.CredentialDEK).
func NewDBConnectorResolver(db *gorm.DB, enc crypto.Encryptor) *DBConnectorResolver {
	return &DBConnectorResolver{db: db, enc: enc, lookup: access.GetAccessConnector}
}

// ConnectorAAD returns the additional-authenticated-data that binds a sealed
// secret envelope to its connector row.
func ConnectorAAD(connectorID uuid.UUID) []byte {
	return []byte("access_connector:" + connectorID.String())
}

// Resolve implements ConnectorResolver.
func (r *DBConnectorResolver) Resolve(ctx context.Context, workspaceID, connectorID uuid.UUID) (*ResolvedConnector, error) {
	var row models.AccessConnector
	err := r.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, connectorID).
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: connector %s not found", ErrConnectorNotConfigured, connectorID)
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load connector: %w", err)
	}

	impl, err := r.lookup(row.Provider)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectorNotConfigured, err)
	}

	config := map[string]any{}
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &config); err != nil {
			return nil, fmt.Errorf("lifecycle: decode connector config: %w", err)
		}
	}

	secrets := map[string]any{}
	if row.SecretEnvelope != "" {
		if r.enc == nil {
			return nil, fmt.Errorf("%w: connector has sealed secrets but no encryptor is configured", ErrConnectorNotConfigured)
		}
		plain, err := r.enc.Open(row.SecretEnvelope, ConnectorAAD(connectorID))
		if err != nil {
			// When no DEK is configured the wired encryptor is a
			// PassthroughEncryptor whose Open returns ErrSecretsDisabled. A
			// connector that has sealed secrets but no key to open them is an
			// unusable-by-configuration connector, not an internal fault, so it
			// must classify the same as the nil-encryptor guard above
			// (ErrConnectorNotConfigured → 422). Without this the error falls
			// through to the generic 500 path and misreports a config gap as an
			// internal server error. Genuinely transient/decode failures stay
			// unwrapped (→500).
			if errors.Is(err, crypto.ErrSecretsDisabled) {
				return nil, fmt.Errorf("%w: connector has sealed secrets but credential encryption is disabled (ACCESS_CREDENTIAL_DEK unset)", ErrConnectorNotConfigured)
			}
			return nil, fmt.Errorf("lifecycle: open connector secrets: %w", err)
		}
		if len(plain) > 0 {
			if err := json.Unmarshal(plain, &secrets); err != nil {
				return nil, fmt.Errorf("lifecycle: decode connector secrets: %w", err)
			}
		}
	}

	return &ResolvedConnector{
		Provider: row.Provider,
		Impl:     impl,
		Config:   config,
		Secrets:  secrets,
	}, nil
}
