package access

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/workers"
)

func newMgmtService(t *testing.T) *ConnectorManagementService {
	t.Helper()
	db := newTestDB(t)
	return NewConnectorManagementService(db, PassthroughEncryptor{}, workers.NewPostgresQueue(db))
}

func TestConnectorManagementCreateAndGet(t *testing.T) {
	mock := &MockAccessConnector{}
	SwapConnector(t, "test-provider", mock)
	svc := newMgmtService(t)
	ctx := context.Background()
	ws := uuid.New()

	row, err := svc.Create(ctx, CreateConnectorInput{
		WorkspaceID: ws,
		Provider:    "test-provider",
		DisplayName: "Test",
		Config:      map[string]interface{}{"domain": "example.com"},
		Secrets:     map[string]interface{}{"token": "shh"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if row.Status != ConnectorStatusPending {
		t.Errorf("status = %q, want pending", row.Status)
	}
	if mock.ValidateCalls != 1 {
		t.Errorf("Validate called %d times, want 1", mock.ValidateCalls)
	}
	// Secrets must be sealed, never stored plaintext.
	if row.SecretEnvelope == "" {
		t.Error("SecretEnvelope is empty; secrets were not sealed")
	}

	got, err := svc.Get(ctx, ws, row.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != row.ID {
		t.Errorf("Get returned %s, want %s", got.ID, row.ID)
	}
}

func TestConnectorManagementCreateUnknownProvider(t *testing.T) {
	svc := newMgmtService(t)
	_, err := svc.Create(context.Background(), CreateConnectorInput{
		WorkspaceID: uuid.New(),
		Provider:    "does-not-exist",
	})
	if !errors.Is(err, ErrConnectorNotFound) {
		t.Errorf("Create unknown provider err = %v, want ErrConnectorNotFound", err)
	}
}

func TestConnectorManagementCreateValidationFails(t *testing.T) {
	mock := &MockAccessConnector{FuncValidate: func(context.Context, map[string]interface{}, map[string]interface{}) error {
		return errors.New("bad config")
	}}
	SwapConnector(t, "test-provider", mock)
	svc := newMgmtService(t)

	_, err := svc.Create(context.Background(), CreateConnectorInput{
		WorkspaceID: uuid.New(),
		Provider:    "test-provider",
	})
	if err == nil {
		t.Fatal("Create should fail when Validate fails")
	}
}

// TestConnectorManagementNilEncryptorFailsClosed pins the constructor contract:
// a nil CredentialEncryptor must not nil-panic mid-Create — it falls back to the
// fail-closed disabled encryptor, so Create errors loudly with ErrSecretsDisabled
// (and never persists plaintext) when a caller forgets to wire a DEK.
func TestConnectorManagementNilEncryptorFailsClosed(t *testing.T) {
	SwapConnector(t, "test-provider", &MockAccessConnector{})
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, nil, workers.NewPostgresQueue(db))

	_, err := svc.Create(context.Background(), CreateConnectorInput{
		WorkspaceID: uuid.New(),
		Provider:    "test-provider",
		Secrets:     map[string]interface{}{"token": "shh"},
	})
	if !errors.Is(err, ErrSecretsDisabled) {
		t.Fatalf("Create with nil encryptor err = %v, want ErrSecretsDisabled (fail closed)", err)
	}
}

func TestConnectorManagementTenantIsolation(t *testing.T) {
	SwapConnector(t, "test-provider", &MockAccessConnector{})
	svc := newMgmtService(t)
	ctx := context.Background()
	wsA, wsB := uuid.New(), uuid.New()

	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: wsA, Provider: "test-provider"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Workspace B must not be able to read workspace A's connector.
	if _, err := svc.Get(ctx, wsB, row.ID); !errors.Is(err, ErrConnectorRowNotFound) {
		t.Errorf("cross-tenant Get err = %v, want ErrConnectorRowNotFound", err)
	}
	// Nor trigger work against it.
	if _, err := svc.TriggerSync(ctx, wsB, row.ID); !errors.Is(err, ErrConnectorRowNotFound) {
		t.Errorf("cross-tenant TriggerSync err = %v, want ErrConnectorRowNotFound", err)
	}
	// List for B is empty.
	list, err := svc.List(ctx, wsB)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("workspace B sees %d connectors, want 0", len(list))
	}
}

func TestConnectorManagementTestConnectivity(t *testing.T) {
	connectErr := errors.New("auth failed")
	mock := &MockAccessConnector{}
	SwapConnector(t, "test-provider", mock)
	svc := newMgmtService(t)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider", Secrets: map[string]interface{}{"k": "v"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Success path → active.
	if _, err := svc.TestConnectivity(ctx, ws, row.ID, nil); err != nil {
		t.Fatalf("TestConnectivity: %v", err)
	}
	got, _ := svc.Get(ctx, ws, row.ID)
	if got.Status != ConnectorStatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}

	// Failure path → error status, error returned. The provider-side failure must
	// wrap BOTH the original connect error (so callers can inspect the cause) and
	// ErrConnectorConnectivity (so the handler surfaces it as a 502, not a 500).
	mock.FuncConnect = func(context.Context, map[string]interface{}, map[string]interface{}) error { return connectErr }
	gotErr := func() error { _, e := svc.TestConnectivity(ctx, ws, row.ID, nil); return e }()
	if !errors.Is(gotErr, connectErr) {
		t.Errorf("TestConnectivity err = %v, want it to wrap %v", gotErr, connectErr)
	}
	if !errors.Is(gotErr, ErrConnectorConnectivity) {
		t.Errorf("provider connect failure must be tagged ErrConnectorConnectivity (so the handler returns 502): %v", gotErr)
	}
	got, _ = svc.Get(ctx, ws, row.ID)
	if got.Status != ConnectorStatusError {
		t.Errorf("status = %q, want error", got.Status)
	}
}

// failingDecryptEncryptor seals via the passthrough identity path (so Create
// succeeds and the row carries a non-empty secret envelope) but fails to open,
// simulating a platform-internal fault — e.g. a rotated or unavailable DEK — on
// the subsequent TestConnectivity.
type failingDecryptEncryptor struct{ PassthroughEncryptor }

func (failingDecryptEncryptor) Decrypt(context.Context, string, []byte, []byte, int) ([]byte, error) {
	return nil, errors.New("kms unavailable")
}

// TestConnectorManagementTestConnectivityInternalFaultNotTagged pins that an
// error raised BEFORE the provider is contacted (here, secret decryption
// failing in openConnector) is NOT tagged ErrConnectorConnectivity. The handler
// keys its 502-vs-500 decision on that tag, so mis-tagging an internal fault
// would leak encryption-layer details to the client as a 502.
func TestConnectorManagementTestConnectivityInternalFaultNotTagged(t *testing.T) {
	SwapConnector(t, "test-provider", &MockAccessConnector{})
	db := newTestDB(t)
	ctx := context.Background()
	ws := uuid.New()

	// Seal with passthrough so Create succeeds and the row has a non-empty
	// secret envelope to decrypt later.
	sealSvc := NewConnectorManagementService(db, PassthroughEncryptor{}, workers.NewPostgresQueue(db))
	row, err := sealSvc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider", Secrets: map[string]interface{}{"k": "v"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Open with an encryptor whose Decrypt fails: TestConnectivity must error at
	// openConnector (an internal fault), before any provider call.
	openSvc := NewConnectorManagementService(db, failingDecryptEncryptor{}, workers.NewPostgresQueue(db))
	_, err = openSvc.TestConnectivity(ctx, ws, row.ID, nil)
	if err == nil {
		t.Fatal("TestConnectivity: expected an error from failed secret decryption, got nil")
	}
	if errors.Is(err, ErrConnectorConnectivity) {
		t.Errorf("internal decrypt fault must NOT be tagged ErrConnectorConnectivity (the handler would leak it as a 502): %v", err)
	}
}

// TestConnectorManagementCreateValidationTaggedErrValidation pins that a
// connector Validate failure (a bad client-supplied config) is tagged
// ErrValidation, so the handler maps it to 400 with the actionable message
// rather than a generic 500. Validate is contractually offline, so a failure
// is always a caller fault, never an internal one.
func TestConnectorManagementCreateValidationTaggedErrValidation(t *testing.T) {
	validationErr := errors.New("missing required field: client_id")
	SwapConnector(t, "okta", &MockAccessConnector{
		FuncValidate: func(context.Context, map[string]interface{}, map[string]interface{}) error {
			return validationErr
		},
	})
	db := newTestDB(t)
	ctx := context.Background()
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, workers.NewPostgresQueue(db))

	_, err := svc.Create(ctx, CreateConnectorInput{
		WorkspaceID: uuid.New(),
		Provider:    "okta",
		Secrets:     map[string]interface{}{"k": "v"},
	})
	if err == nil {
		t.Fatal("Create with invalid config: want error, got nil")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("Create validate failure must be tagged ErrValidation (so the handler returns 400, not 500): %v", err)
	}
	if !errors.Is(err, validationErr) {
		t.Errorf("Create error must still wrap the underlying validation cause: %v", err)
	}
}

// TestCatalogueEntryForScopedConnectionEnrichment pins that the single-provider
// detail path enriches connection state from a provider-scoped query: the
// connected provider reports its row, an unconnected provider does not, and the
// lookup never bleeds across tenants.
func TestCatalogueEntryForScopedConnectionEnrichment(t *testing.T) {
	// Register a mock under the real "okta" key (which has a curated descriptor)
	// so Create succeeds and the descriptor lookup in CatalogueEntryFor resolves.
	SwapConnector(t, "okta", &MockAccessConnector{})
	db := newTestDB(t)
	ctx := context.Background()
	ws := uuid.New()

	mgmt := NewConnectorManagementService(db, PassthroughEncryptor{}, workers.NewPostgresQueue(db))
	row, err := mgmt.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "okta", Secrets: map[string]interface{}{"k": "v"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	cat := NewAccessConnectorCatalogueService(db)

	// Connected provider → enriched with the row id + status.
	entry, ok, err := cat.CatalogueEntryFor(ctx, ws, "okta")
	if err != nil || !ok {
		t.Fatalf("CatalogueEntryFor(okta) ok=%v err=%v", ok, err)
	}
	if !entry.Connected || entry.ConnectorID != row.ID.String() {
		t.Errorf("okta entry not enriched with connection: %+v", entry)
	}

	// A different curated provider the workspace has NOT connected must report
	// Connected=false — the provider-scoped query must not match okta's row.
	other, ok, err := cat.CatalogueEntryFor(ctx, ws, "auth0")
	if err != nil || !ok {
		t.Fatalf("CatalogueEntryFor(auth0) ok=%v err=%v", ok, err)
	}
	if other.Connected {
		t.Errorf("unconnected provider reported Connected=true: %+v", other)
	}

	// Cross-tenant: another workspace sees okta as not connected.
	entryB, ok, err := cat.CatalogueEntryFor(ctx, uuid.New(), "okta")
	if err != nil || !ok {
		t.Fatalf("CatalogueEntryFor cross-tenant ok=%v err=%v", ok, err)
	}
	if entryB.Connected {
		t.Errorf("cross-tenant entry reported Connected=true: %+v", entryB)
	}
}

// TestConnectorManagementTestConnectivityPersistFailureDoesNotLeak pins that when
// the provider connectivity test fails AND persisting the resulting status fails,
// the caller still receives the connectivity diagnostic (so it routes to a 502)
// but the raw DB/persistence error is NOT folded into that client-facing error —
// it would leak schema details (table/column names) in the 502 body. The
// persistence failure is logged server-side instead.
func TestConnectorManagementTestConnectivityPersistFailureDoesNotLeak(t *testing.T) {
	connectErr := errors.New("auth failed")
	mock := &MockAccessConnector{}
	SwapConnector(t, "test-provider", mock)
	svc := newMgmtService(t)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider", Secrets: map[string]interface{}{"k": "v"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Connect runs after the row is loaded but before the status UPDATE. Drop
	// the table here so the subsequent persistence write fails while the
	// connectivity error is also non-nil.
	mock.FuncConnect = func(context.Context, map[string]interface{}, map[string]interface{}) error {
		if e := svc.db.WithContext(ctx).Exec("DROP TABLE access_connectors").Error; e != nil {
			t.Fatalf("drop table: %v", e)
		}
		return connectErr
	}

	_, err = svc.TestConnectivity(ctx, ws, row.ID, nil)
	if err == nil {
		t.Fatal("TestConnectivity: expected error, got nil")
	}
	// The caller still gets the tagged connectivity diagnostic (→ 502).
	if !errors.Is(err, connectErr) {
		t.Errorf("returned error does not wrap connectivity error: %v", err)
	}
	if !errors.Is(err, ErrConnectorConnectivity) {
		t.Errorf("returned error is not tagged ErrConnectorConnectivity: %v", err)
	}
	// But the persistence failure must NOT bleed into the client-facing error:
	// no "persist connectivity status" wrapper, no leaked table name.
	if strings.Contains(err.Error(), "persist connectivity status") {
		t.Errorf("persistence failure leaked into client-facing error: %v", err)
	}
	if strings.Contains(err.Error(), "access_connectors") {
		t.Errorf("DB schema detail (table name) leaked into client-facing error: %v", err)
	}
}

// TestConnectorManagementTestConnectivityMissingScopesIsDegradedNotError pins the
// OpenAPI contract: a connector whose Connect succeeds but whose VerifyPermissions
// reports unmet scopes is NOT a connectivity failure. TestConnectivity must return
// the missing list with a NIL error (so the handler returns 200, not 502) and
// persist the row as degraded (connected, but missing a grant) — never error.
func TestConnectorManagementTestConnectivityMissingScopesIsDegradedNotError(t *testing.T) {
	mock := &MockAccessConnector{
		FuncVerifyPermissions: func(context.Context, map[string]interface{}, map[string]interface{}, []string) ([]string, error) {
			return []string{"groups:read"}, nil
		},
	}
	SwapConnector(t, "test-provider", mock)
	svc := newMgmtService(t)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider", Secrets: map[string]interface{}{"k": "v"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	missing, err := svc.TestConnectivity(ctx, ws, row.ID, []string{"users:read", "groups:read"})
	if err != nil {
		t.Fatalf("missing scopes must NOT be an error (handler returns 200), got: %v", err)
	}
	if len(missing) != 1 || missing[0] != "groups:read" {
		t.Errorf("missing = %v, want [groups:read]", missing)
	}
	got, _ := svc.Get(ctx, ws, row.ID)
	if got.Status != ConnectorStatusDegraded {
		t.Errorf("status = %q, want degraded (connected but missing a scope)", got.Status)
	}
}

func TestConnectorManagementTriggerSyncEnqueues(t *testing.T) {
	SwapConnector(t, "test-provider", &MockAccessConnector{})
	db := newTestDB(t)
	queue := workers.NewPostgresQueue(db)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, queue)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	jobID, err := svc.TriggerSync(ctx, ws, row.ID)
	if err != nil {
		t.Fatalf("TriggerSync: %v", err)
	}
	if jobID == "" {
		t.Fatal("TriggerSync returned empty job id")
	}
	// The job is claimable from the queue.
	jobs, err := queue.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Type != JobTypeSyncIdentities {
		t.Errorf("claimed jobs = %+v, want 1 sync_identities job", jobs)
	}
}

func TestConnectorManagementDisconnect(t *testing.T) {
	SwapConnector(t, "test-provider", &MockAccessConnector{})
	svc := newMgmtService(t)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider", Secrets: map[string]interface{}{"k": "v"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Disconnect(ctx, ws, row.ID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	// Soft-deleted: Get no longer finds it.
	if _, err := svc.Get(ctx, ws, row.ID); !errors.Is(err, ErrConnectorRowNotFound) {
		t.Errorf("Get after Disconnect err = %v, want ErrConnectorRowNotFound", err)
	}
	// The secret envelope was cleared on the soft-deleted row.
	var raw models.AccessConnector
	if err := svc.db.Unscoped().First(&raw, "id = ?", row.ID).Error; err != nil {
		t.Fatalf("load soft-deleted row: %v", err)
	}
	if raw.SecretEnvelope != "" {
		t.Error("SecretEnvelope was not cleared on disconnect")
	}
}

// newMgmtWithSSO builds a management service whose SSO federation is backed by
// the supplied in-memory ConnectionConfigurator, so the connector SSO endpoints
// can be exercised without a live iam-core.
func newMgmtWithSSO(t *testing.T, conns ConnectionConfigurator) *ConnectorManagementService {
	t.Helper()
	db := newTestDB(t)
	return NewConnectorManagementService(db, PassthroughEncryptor{}, workers.NewPostgresQueue(db),
		WithSSOFederation(NewSSOFederationService(conns)))
}

// TestConnectorManagementConfigureSSOFederation pins the happy path: the
// connector's advertised SSO metadata is federated into an iam-core Connection,
// the connection's id is persisted on the row (so teardown can remove it), and
// no federation secret is leaked back through the connection name.
func TestConnectorManagementConfigureSSOFederation(t *testing.T) {
	mock := &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			return &SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration", EntityID: "idp-entity"}, nil
		},
	}
	SwapConnector(t, "okta", mock) // "okta" → iam-core strategy "oidc"
	fake := &fakeConnections{}
	svc := newMgmtWithSSO(t, fake)
	ctx := context.Background()
	ws := uuid.New()

	row, err := svc.Create(ctx, CreateConnectorInput{
		WorkspaceID: ws,
		Provider:    "okta",
		DisplayName: "Corp Okta",
		Secrets:     map[string]interface{}{"sso_client_id": "cid", "sso_client_secret": "sec"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	conn, err := svc.ConfigureSSOFederation(ctx, ws, row.ID)
	if err != nil {
		t.Fatalf("ConfigureSSOFederation: %v", err)
	}
	if conn.ID != "conn-123" {
		t.Errorf("connection id = %q, want conn-123", conn.ID)
	}
	if conn.Strategy != "oidc" {
		t.Errorf("strategy = %q, want oidc", conn.Strategy)
	}
	if mock.GetSSOMetadataCalls != 1 {
		t.Errorf("GetSSOMetadata called %d times, want 1", mock.GetSSOMetadataCalls)
	}
	wantName := "shieldnet-okta-" + ws.String()
	if fake.created == nil || fake.created.Name != wantName {
		t.Errorf("created connection name = %v, want %q", fake.created, wantName)
	}
	if fake.created.Options["client_id"] != "cid" {
		t.Errorf("client_id option = %v, want cid", fake.created.Options["client_id"])
	}
	// The connection id must be persisted so teardown can remove it.
	got, err := svc.Get(ctx, ws, row.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SSOConnectionID != "conn-123" {
		t.Errorf("SSOConnectionID = %q, want conn-123 (persisted)", got.SSOConnectionID)
	}
}

// TestConnectorManagementConfigureSSOUnsupported pins that a connector which
// does not federate SSO (GetSSOMetadata → nil) surfaces ErrSSOFederationUnsupported
// (handler → 422) and persists no connection id.
func TestConnectorManagementConfigureSSOUnsupported(t *testing.T) {
	mock := &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			return nil, nil
		},
	}
	SwapConnector(t, "test-provider", mock)
	fake := &fakeConnections{}
	svc := newMgmtWithSSO(t, fake)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider", Secrets: map[string]interface{}{"k": "v"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := svc.ConfigureSSOFederation(ctx, ws, row.ID); !errors.Is(err, ErrSSOFederationUnsupported) {
		t.Errorf("ConfigureSSOFederation err = %v, want ErrSSOFederationUnsupported", err)
	}
	if fake.created != nil {
		t.Error("no iam-core connection should be created for a non-federating connector")
	}
	got, _ := svc.Get(ctx, ws, row.ID)
	if got.SSOConnectionID != "" {
		t.Errorf("SSOConnectionID = %q, want empty (nothing federated)", got.SSOConnectionID)
	}
}

// TestConnectorManagementConfigureSSODisabled pins that when SSO federation is
// not wired (no iam-core management client), the endpoint fails-soft with
// ErrSSOFederationDisabled (handler → 503) rather than panicking — for both a
// service built with no SSO option and one built around a nil configurator.
func TestConnectorManagementConfigureSSODisabled(t *testing.T) {
	SwapConnector(t, "test-provider", &MockAccessConnector{})
	ctx := context.Background()

	// (a) No WithSSOFederation option at all.
	svc := newMgmtService(t)
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.ConfigureSSOFederation(ctx, ws, row.ID); !errors.Is(err, ErrSSOFederationDisabled) {
		t.Errorf("ConfigureSSOFederation (no sso) err = %v, want ErrSSOFederationDisabled", err)
	}
	if err := svc.RemoveSSOFederation(ctx, ws, row.ID); !errors.Is(err, ErrSSOFederationDisabled) {
		t.Errorf("RemoveSSOFederation (no sso) err = %v, want ErrSSOFederationDisabled", err)
	}

	// (b) WithSSOFederation around a nil configurator (the production wiring when
	// iam-core management is unconfigured): the federation service itself must
	// fail-soft, never nil-panic.
	svc2 := newMgmtWithSSO(t, nil)
	ws2 := uuid.New()
	row2, err := svc2.Create(ctx, CreateConnectorInput{WorkspaceID: ws2, Provider: "test-provider"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc2.ConfigureSSOFederation(ctx, ws2, row2.ID); !errors.Is(err, ErrSSOFederationDisabled) {
		t.Errorf("ConfigureSSOFederation (nil configurator) err = %v, want ErrSSOFederationDisabled", err)
	}
}

// TestConnectorManagementConfigureSSOReconfigureRemovesStale pins that
// re-configuring a connector that already has a federated connection removes the
// stale connection first (so iam-core never collides on the stable name and no
// connection is orphaned) and records the freshly-created id.
func TestConnectorManagementConfigureSSOReconfigureRemovesStale(t *testing.T) {
	mock := &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			return &SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration"}, nil
		},
	}
	SwapConnector(t, "okta", mock)
	fake := &fakeConnections{}
	svc := newMgmtWithSSO(t, fake)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "okta", Secrets: map[string]interface{}{"sso_client_id": "cid"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Pretend a prior federation exists on the row.
	if err := svc.db.Model(&models.AccessConnector{}).Where("id = ?", row.ID).Update("sso_connection_id", "stale-conn").Error; err != nil {
		t.Fatalf("seed stale connection id: %v", err)
	}

	if _, err := svc.ConfigureSSOFederation(ctx, ws, row.ID); err != nil {
		t.Fatalf("ConfigureSSOFederation: %v", err)
	}
	if fake.deletedID != "stale-conn" {
		t.Errorf("stale connection deleted = %q, want stale-conn", fake.deletedID)
	}
	got, _ := svc.Get(ctx, ws, row.ID)
	if got.SSOConnectionID != "conn-123" {
		t.Errorf("SSOConnectionID = %q, want conn-123 (re-federated)", got.SSOConnectionID)
	}
}

// TestConnectorManagementConfigureSSORollbackOnPersistFailure pins that if the
// iam-core connection is created but persisting its id fails, the orphaned
// connection is rolled back (removed) so a retry is not blocked by a duplicate
// name and no un-removable connection is leaked.
func TestConnectorManagementConfigureSSORollbackOnPersistFailure(t *testing.T) {
	fake := &fakeConnections{}
	svc := newMgmtWithSSO(t, fake)
	ctx := context.Background()
	ws := uuid.New()
	mock := &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			// Drop the table here — inside ConfigureSSO, after loadConnector /
			// openConnector but before the sso_connection_id UPDATE — so the
			// persist write fails while the connection has already been created.
			if e := svc.db.WithContext(ctx).Exec("DROP TABLE access_connectors").Error; e != nil {
				t.Fatalf("drop table: %v", e)
			}
			return &SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration"}, nil
		},
	}
	SwapConnector(t, "okta", mock)
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "okta", Secrets: map[string]interface{}{"sso_client_id": "cid"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := svc.ConfigureSSOFederation(ctx, ws, row.ID); err == nil {
		t.Fatal("ConfigureSSOFederation: expected persist failure, got nil")
	}
	if fake.deletedID != "conn-123" {
		t.Errorf("created connection not rolled back: deletedID = %q, want conn-123", fake.deletedID)
	}
}

// TestConnectorManagementRemoveSSOFederation pins the explicit teardown
// endpoint: it removes the iam-core connection, clears the recorded id, and is
// idempotent (a second call is a no-op, never a redundant delete).
func TestConnectorManagementRemoveSSOFederation(t *testing.T) {
	mock := &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			return &SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration"}, nil
		},
	}
	SwapConnector(t, "okta", mock)
	fake := &fakeConnections{}
	svc := newMgmtWithSSO(t, fake)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "okta", Secrets: map[string]interface{}{"sso_client_id": "cid"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.ConfigureSSOFederation(ctx, ws, row.ID); err != nil {
		t.Fatalf("ConfigureSSOFederation: %v", err)
	}

	if err := svc.RemoveSSOFederation(ctx, ws, row.ID); err != nil {
		t.Fatalf("RemoveSSOFederation: %v", err)
	}
	if fake.deletedID != "conn-123" {
		t.Errorf("removed connection = %q, want conn-123", fake.deletedID)
	}
	got, _ := svc.Get(ctx, ws, row.ID)
	if got.SSOConnectionID != "" {
		t.Errorf("SSOConnectionID = %q, want empty after removal", got.SSOConnectionID)
	}

	// Idempotent: a second removal with nothing federated must not call
	// DeleteConnection again.
	fake.deletedID = "sentinel"
	if err := svc.RemoveSSOFederation(ctx, ws, row.ID); err != nil {
		t.Fatalf("RemoveSSOFederation (idempotent): %v", err)
	}
	if fake.deletedID != "sentinel" {
		t.Errorf("idempotent removal must not delete again: deletedID = %q", fake.deletedID)
	}
}

// TestConnectorManagementDisconnectRemovesSSO pins that disconnecting a
// connector tears down its federated iam-core connection (no orphan) and clears
// the recorded id on the soft-deleted row.
func TestConnectorManagementDisconnectRemovesSSO(t *testing.T) {
	mock := &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			return &SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration"}, nil
		},
	}
	SwapConnector(t, "okta", mock)
	fake := &fakeConnections{}
	svc := newMgmtWithSSO(t, fake)
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "okta", Secrets: map[string]interface{}{"sso_client_id": "cid"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.ConfigureSSOFederation(ctx, ws, row.ID); err != nil {
		t.Fatalf("ConfigureSSOFederation: %v", err)
	}

	if err := svc.Disconnect(ctx, ws, row.ID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if fake.deletedID != "conn-123" {
		t.Errorf("disconnect did not remove federated connection: deletedID = %q, want conn-123", fake.deletedID)
	}
	var raw models.AccessConnector
	if err := svc.db.Unscoped().First(&raw, "id = ?", row.ID).Error; err != nil {
		t.Fatalf("load soft-deleted row: %v", err)
	}
	if raw.SSOConnectionID != "" {
		t.Error("SSOConnectionID was not cleared on disconnect")
	}
}

// TestConnectorManagementConfigureSSOTenantIsolation pins that a workspace can
// never federate (or tear down) another tenant's connector.
func TestConnectorManagementConfigureSSOTenantIsolation(t *testing.T) {
	mock := &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			return &SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration"}, nil
		},
	}
	SwapConnector(t, "okta", mock)
	fake := &fakeConnections{}
	svc := newMgmtWithSSO(t, fake)
	ctx := context.Background()
	wsA, wsB := uuid.New(), uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: wsA, Provider: "okta", Secrets: map[string]interface{}{"sso_client_id": "cid"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := svc.ConfigureSSOFederation(ctx, wsB, row.ID); !errors.Is(err, ErrConnectorRowNotFound) {
		t.Errorf("cross-tenant ConfigureSSOFederation err = %v, want ErrConnectorRowNotFound", err)
	}
	if err := svc.RemoveSSOFederation(ctx, wsB, row.ID); !errors.Is(err, ErrConnectorRowNotFound) {
		t.Errorf("cross-tenant RemoveSSOFederation err = %v, want ErrConnectorRowNotFound", err)
	}
	// And nothing was federated as a side effect.
	if fake.created != nil {
		t.Error("cross-tenant call must not create an iam-core connection")
	}
}
