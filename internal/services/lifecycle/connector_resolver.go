package lifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// DBConnectorResolver is the production ConnectorResolver. It loads a connector
// row (workspace-scoped), then opens its JSON config and AES-GCM sealed secret
// envelope through access.OpenConnectorRow — the same canonical path the
// connector-management layer uses to seal them — and looks up the registered
// AccessConnector implementation from the process-global registry.
//
// Opening through the shared access helper (rather than re-deriving the cipher
// inputs here) is what guarantees the open path can never drift from the seal
// path: same connector-id AAD, same workspace DEK, same persisted key version.
type DBConnectorResolver struct {
	db  *gorm.DB
	enc access.CredentialEncryptor
	// lookup resolves a provider key to its implementation; defaults to the
	// process-global registry but is overridable in tests.
	lookup func(provider string) (access.AccessConnector, error)
}

// NewDBConnectorResolver wires the resolver to the DB and the credential
// encryptor (built from config.CredentialDEK, the same CredentialEncryptor the
// connector-management service seals secrets with).
func NewDBConnectorResolver(db *gorm.DB, enc access.CredentialEncryptor) *DBConnectorResolver {
	return &DBConnectorResolver{db: db, enc: enc, lookup: access.GetAccessConnector}
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

	if row.SecretEnvelope != "" && r.enc == nil {
		return nil, fmt.Errorf("%w: connector has sealed secrets but no encryptor is configured", ErrConnectorNotConfigured)
	}

	config, secrets, err := access.OpenConnectorRow(ctx, r.enc, &row)
	if err != nil {
		// When no DEK is configured the wired encryptor is the fail-closed
		// disabledEncryptor whose Decrypt returns access.ErrSecretsDisabled. A
		// connector that has sealed secrets but no key to open them is an
		// unusable-by-configuration connector, not an internal fault, so it
		// must classify the same as the nil-encryptor guard above
		// (ErrConnectorNotConfigured → 422). Without this the error falls
		// through to the generic 500 path and misreports a config gap as an
		// internal server error. Genuinely transient/decode failures stay
		// unwrapped (→500).
		if errors.Is(err, access.ErrSecretsDisabled) {
			return nil, fmt.Errorf("%w: connector has sealed secrets but credential encryption is disabled (ACCESS_CREDENTIAL_DEK unset)", ErrConnectorNotConfigured)
		}
		return nil, fmt.Errorf("lifecycle: open connector secrets: %w", err)
	}

	return &ResolvedConnector{
		Provider: row.Provider,
		Impl:     impl,
		Config:   config,
		Secrets:  secrets,
	}, nil
}
