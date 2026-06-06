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

	// Failure path → error status, error returned.
	mock.FuncConnect = func(context.Context, map[string]interface{}, map[string]interface{}) error { return connectErr }
	if _, err := svc.TestConnectivity(ctx, ws, row.ID, nil); !errors.Is(err, connectErr) {
		t.Errorf("TestConnectivity err = %v, want %v", err, connectErr)
	}
	got, _ = svc.Get(ctx, ws, row.ID)
	if got.Status != ConnectorStatusError {
		t.Errorf("status = %q, want error", got.Status)
	}
}

// TestConnectorManagementTestConnectivityJoinsErrors pins that when the provider
// connectivity test fails AND persisting the resulting status fails, the
// returned error surfaces BOTH causes. Previously only the DB error was
// returned, silently dropping the connectivity diagnosis an operator needs.
func TestConnectorManagementTestConnectivityJoinsErrors(t *testing.T) {
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
	if !errors.Is(err, connectErr) {
		t.Errorf("returned error does not wrap connectivity error: %v", err)
	}
	if !strings.Contains(err.Error(), "persist connectivity status") {
		t.Errorf("returned error does not include the DB persistence failure: %v", err)
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
