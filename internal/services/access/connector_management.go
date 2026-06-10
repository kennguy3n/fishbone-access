package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Connector lifecycle status values persisted in access_connectors.status.
const (
	// ConnectorStatusPending is a freshly-created connector that has not yet
	// passed a live connectivity test.
	ConnectorStatusPending = "pending"
	// ConnectorStatusActive is a connector whose credentials verified against
	// the provider.
	ConnectorStatusActive = "active"
	// ConnectorStatusError is a connector whose last connectivity test failed.
	ConnectorStatusError = "error"
	// ConnectorStatusDegraded is a connector whose credentials verified against
	// the provider (Connect succeeded) but which is missing one or more of the
	// requested capability scopes. The connection works; it just cannot perform
	// every function yet. This is distinct from "error" (a real connectivity
	// failure) so the catalogue/UI can show "connected, needs a scope" rather
	// than a red failure for a connector that is actually reachable.
	ConnectorStatusDegraded = "degraded"
)

// Job type values the worker dispatches on. They are the access_jobs.type
// column and the discriminator the ConnectorJobProcessor switches on.
const (
	JobTypeSyncIdentities = "sync_identities"
	JobTypeProvision      = "provision_access"
	JobTypeRevoke         = "revoke_access"
)

// JobEnqueuer is the subset of the worker queue the management service needs to
// schedule background work. The Postgres-backed workers.PostgresQueue satisfies
// it; tests inject a fake. Defining it here keeps the access package free of a
// hard dependency on a concrete queue implementation.
type JobEnqueuer interface {
	Enqueue(ctx context.Context, workspaceID, connectorID uuid.UUID, jobType string, payload []byte) (string, error)
}

// ConnectorManagementService owns the connector lifecycle: create (with
// validation + secret sealing), live connectivity testing, sync scheduling, and
// teardown. Every operation is scoped by workspace_id so one tenant can never
// read, mutate, or trigger work against another tenant's connectors.
type ConnectorManagementService struct {
	db    *gorm.DB
	enc   CredentialEncryptor
	queue JobEnqueuer
}

// NewConnectorManagementService builds the service. enc seals/opens connector
// secrets; a nil enc falls back to the fail-closed disabled encryptor (so a
// missing DEK wiring errors loudly rather than persisting plaintext or
// panicking). queue schedules sync/provision/revoke jobs (may be nil if the
// caller never triggers background work).
func NewConnectorManagementService(db *gorm.DB, enc CredentialEncryptor, queue JobEnqueuer) *ConnectorManagementService {
	// A nil encryptor must fail CLOSED, not nil-panic mid-Create/openConnector:
	// substitute the disabled encryptor so a forgotten DEK wiring surfaces as a
	// loud ErrSecretsDisabled (never a plaintext write or a crash). The
	// production binaries pass CredentialEncryptorFromKey (which yields the
	// disabled encryptor for an empty key, never nil) and tests pass
	// PassthroughEncryptor, so this guard only trips if a future caller forgets
	// to wire one — and when it does, the platform stays secure by default.
	if enc == nil {
		enc = NewDisabledEncryptor()
	}
	return &ConnectorManagementService{db: db, enc: enc, queue: queue}
}

// CreateConnectorInput is the payload for Create.
type CreateConnectorInput struct {
	WorkspaceID uuid.UUID
	Provider    string
	DisplayName string
	Config      map[string]interface{}
	Secrets     map[string]interface{}
}

// Create validates the configuration against the provider connector, seals the
// secrets under the workspace DEK, and persists a pending connector row. It does
// NOT perform network I/O (Validate is contractually offline); call
// TestConnectivity to verify credentials against the live provider.
func (s *ConnectorManagementService) Create(ctx context.Context, in CreateConnectorInput) (*models.AccessConnector, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("access: ConnectorManagementService not initialised")
	}
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("access: Create: workspaceID required")
	}
	connector, err := GetAccessConnector(in.Provider)
	if err != nil {
		return nil, fmt.Errorf("access: Create: %w", err)
	}
	if err := connector.Validate(ctx, in.Config, in.Secrets); err != nil {
		// Validate is contractually offline: a failure here is a bad
		// client-supplied config/secret (missing client_id, malformed field),
		// not an internal fault. Tag it with ErrValidation so the handler maps
		// it to 400 with the actionable message, instead of the generic 500
		// the default path returns. The cause stays in the chain, so
		// errors.Is still matches both ErrValidation and the connector error.
		return nil, fmt.Errorf("%w: validate config: %w", ErrValidation, err)
	}

	// Generate the row id up front so it can be bound as the AES-GCM AAD: the
	// sealed envelope is then cryptographically tied to this exact row and
	// cannot be copied to another connector.
	id := uuid.New()
	envelope, keyVersion, encErr := encryptSecretsMap(ctx, s.enc, in.WorkspaceID.String(), in.Secrets, id.String())
	if encErr != nil {
		return nil, encErr
	}
	cfgJSON, err := marshalConfig(in.Config)
	if err != nil {
		return nil, err
	}

	row := models.AccessConnector{
		Base:             models.Base{ID: id},
		WorkspaceID:      in.WorkspaceID,
		Provider:         in.Provider,
		DisplayName:      in.DisplayName,
		Status:           ConnectorStatusPending,
		Config:           cfgJSON,
		SecretEnvelope:   envelope,
		SecretKeyVersion: keyVersion,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return nil, fmt.Errorf("access: create connector: %w", err)
	}
	return &row, nil
}

// Get returns a connector by id, scoped to workspaceID. A row in another
// workspace is indistinguishable from a missing row (ErrConnectorRowNotFound).
func (s *ConnectorManagementService) Get(ctx context.Context, workspaceID, connectorID uuid.UUID) (*models.AccessConnector, error) {
	return s.loadConnector(ctx, s.db, workspaceID, connectorID)
}

// List returns every connector in the workspace, newest first.
func (s *ConnectorManagementService) List(ctx context.Context, workspaceID uuid.UUID) ([]models.AccessConnector, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("access: ConnectorManagementService not initialised")
	}
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("access: List: workspaceID required")
	}
	var rows []models.AccessConnector
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("access: list connectors: %w", err)
	}
	return rows, nil
}

// TestConnectivity opens the stored secrets and runs the provider's Connect (and
// VerifyPermissions when capabilities are supplied), persisting the connector's
// status: active when the connection works and all requested scopes are present,
// degraded when it connects but some scopes are missing, error when the provider
// rejects the connection. The returned error is non-nil ONLY for a genuine
// connectivity failure (tagged ErrConnectorConnectivity); a connect-OK / missing-
// scopes result returns the missing list with a nil error so the caller can
// report it as a 200 success. The status is persisted regardless.
func (s *ConnectorManagementService) TestConnectivity(ctx context.Context, workspaceID, connectorID uuid.UUID, capabilities []string) (missing []string, err error) {
	row, err := s.loadConnector(ctx, s.db, workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	connector, err := GetAccessConnector(row.Provider)
	if err != nil {
		return nil, fmt.Errorf("access: TestConnectivity: %w", err)
	}
	cfg, secrets, err := s.openConnector(ctx, row)
	if err != nil {
		return nil, err
	}

	connectErr := connector.Connect(ctx, cfg, secrets)
	if connectErr == nil && len(capabilities) > 0 {
		missing, connectErr = connector.VerifyPermissions(ctx, cfg, secrets, capabilities)
	}
	// Everything above this point that errored (loadConnector, GetAccessConnector,
	// openConnector) returned early as an internal/registry fault. connectErr is
	// the only error that originates from the provider side, so tag a genuine
	// provider failure with ErrConnectorConnectivity: the handler surfaces that
	// as a 502 with the raw diagnostic, while untagged faults fall through to a
	// generic 500 and never leak the decrypt/config internals to the client.
	//
	// A successful Connect whose VerifyPermissions reports unmet scopes is NOT a
	// connectivity failure — the credentials work, the connector is merely
	// missing a grant. That case carries a nil error and is reported to the
	// operator via `missing`, so the handler returns 200 per the OpenAPI
	// contract (docs/openapi.yaml: "Connection succeeded (missing lists any
	// unmet capabilities)") and the row is marked degraded rather than error.
	if connectErr != nil {
		connectErr = fmt.Errorf("%w: %w", ErrConnectorConnectivity, connectErr)
	}

	status := ConnectorStatusActive
	switch {
	case connectErr != nil:
		status = ConnectorStatusError
	case len(missing) > 0:
		status = ConnectorStatusDegraded
	}
	if uerr := s.db.WithContext(ctx).
		Model(&models.AccessConnector{}).
		Where("id = ? AND workspace_id = ?", row.ID, workspaceID).
		Update("status", status).Error; uerr != nil {
		// The status write is a platform-internal operation; its failure must
		// not be folded into the client-facing connectivity diagnostic, or a
		// GORM/driver error (table/column names) would leak in the 502 body via
		// the handler's err.Error(). Log it server-side for ops and return only
		// the provider diagnostic (connectErr) to the caller. When connectErr is
		// nil (a pure persistence failure), return the wrapped DB error UNtagged
		// so the handler routes it through its generic-500 path, which logs the
		// detail but returns an opaque "internal error" body.
		logger.Errorf(ctx, "access: persist connectivity status for connector %s (workspace %s): %v", row.ID, workspaceID, uerr)
		if connectErr != nil {
			return missing, connectErr
		}
		return missing, fmt.Errorf("access: persist connectivity status: %w", uerr)
	}
	return missing, connectErr
}

// TriggerSync enqueues an identity-sync job for the connector. It verifies the
// connector belongs to the workspace before scheduling so a caller cannot queue
// work against another tenant's connector.
func (s *ConnectorManagementService) TriggerSync(ctx context.Context, workspaceID, connectorID uuid.UUID) (jobID string, err error) {
	if s.queue == nil {
		return "", fmt.Errorf("access: TriggerSync: no job queue configured")
	}
	row, err := s.loadConnector(ctx, s.db, workspaceID, connectorID)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(jobPayload{
		WorkspaceID: row.WorkspaceID.String(),
		ConnectorID: row.ID.String(),
		SyncType:    DefaultSyncType,
	})
	if err != nil {
		return "", fmt.Errorf("access: marshal sync payload: %w", err)
	}
	return s.queue.Enqueue(ctx, row.WorkspaceID, row.ID, JobTypeSyncIdentities, payload)
}

// Disconnect soft-deletes a connector after verifying it belongs to the
// workspace. The encrypted secret envelope is cleared so a soft-deleted row
// retains no recoverable credentials.
func (s *ConnectorManagementService) Disconnect(ctx context.Context, workspaceID, connectorID uuid.UUID) error {
	row, err := s.loadConnector(ctx, s.db, workspaceID, connectorID)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.AccessConnector{}).
			Where("id = ? AND workspace_id = ?", row.ID, workspaceID).
			Updates(map[string]any{"secret_envelope": "", "status": ConnectorStatusPending}).Error; err != nil {
			return fmt.Errorf("access: clear connector secrets: %w", err)
		}
		if err := tx.Where("id = ? AND workspace_id = ?", row.ID, workspaceID).
			Delete(&models.AccessConnector{}).Error; err != nil {
			return fmt.Errorf("access: delete connector: %w", err)
		}
		return nil
	})
}

// loadConnector fetches a connector scoped to workspaceID, mapping a missing row
// (including a row owned by another workspace) to ErrConnectorRowNotFound.
func (s *ConnectorManagementService) loadConnector(ctx context.Context, db *gorm.DB, workspaceID, connectorID uuid.UUID) (*models.AccessConnector, error) {
	if s == nil || db == nil {
		return nil, fmt.Errorf("access: ConnectorManagementService not initialised")
	}
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return nil, fmt.Errorf("access: loadConnector: workspace and connector are required")
	}
	var row models.AccessConnector
	err := db.WithContext(ctx).
		Where("id = ? AND workspace_id = ?", connectorID, workspaceID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrConnectorRowNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("access: load connector: %w", err)
	}
	return &row, nil
}

// openConnector decodes a connector row's config and opens its sealed secrets,
// returning the maps the AccessConnector methods expect. It is the single point
// where connector secrets are decrypted, immediately before a provider call.
func (s *ConnectorManagementService) openConnector(ctx context.Context, row *models.AccessConnector) (config, secrets map[string]interface{}, err error) {
	return OpenConnectorRow(ctx, s.enc, row)
}

// OpenConnectorRow decodes a connector row's JSON config and opens its sealed
// secret envelope, returning the (config, secrets) maps the AccessConnector
// protocol methods expect. It is the single canonical way to recover a
// connector's plaintext credentials from its persisted row and is shared by the
// connector-management service AND the lifecycle connector resolver.
//
// Sharing one path is deliberate: the envelope is sealed under AES-256-GCM with
// the connector row id as AAD, the workspace DEK, and a persisted key version.
// Any caller that re-derives those inputs independently risks drifting from the
// seal path (a mismatched AAD or wrong key surfaces as an opaque
// "message authentication failed" 500). Routing every open through this helper
// makes such drift impossible. A nil/empty envelope yields an empty secrets map
// (a connector configured with no secrets), never an error.
func OpenConnectorRow(ctx context.Context, enc CredentialEncryptor, row *models.AccessConnector) (config, secrets map[string]interface{}, err error) {
	config, err = unmarshalConfig(row.Config)
	if err != nil {
		return nil, nil, err
	}
	secrets, err = decryptSecretsMap(ctx, enc, row.WorkspaceID.String(), row.SecretEnvelope, row.ID.String(), row.SecretKeyVersion)
	if err != nil {
		return nil, nil, err
	}
	return config, secrets, nil
}

// jobPayload is the JSON persisted in access_jobs.payload and decoded by the
// ConnectorJobProcessor. WorkspaceID is carried in the payload (not only the
// row column) so the processor enforces tenant scoping from a single source.
type jobPayload struct {
	WorkspaceID string       `json:"workspace_id"`
	ConnectorID string       `json:"connector_id"`
	SyncType    string       `json:"sync_type,omitempty"`
	Grant       *AccessGrant `json:"grant,omitempty"`
}

func marshalConfig(cfg map[string]interface{}) (datatypes.JSON, error) {
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("access: marshal config: %w", err)
	}
	return datatypes.JSON(b), nil
}

func unmarshalConfig(raw datatypes.JSON) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("access: unmarshal config: %w", err)
	}
	return out, nil
}
