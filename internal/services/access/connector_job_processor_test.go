package access

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/workers"
)

// enqueueAndClaim creates a connector, enqueues a job of the given type/payload,
// and returns the claimed workers.Job plus the service for assertions.
func makeJob(t *testing.T, svc *ConnectorManagementService, ws uuid.UUID, connID uuid.UUID, jobType string, grant *AccessGrant, syncType string) workers.Job {
	t.Helper()
	payload, err := json.Marshal(jobPayload{
		WorkspaceID: ws.String(),
		ConnectorID: connID.String(),
		SyncType:    syncType,
		Grant:       grant,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return workers.Job{ID: uuid.New().String(), Type: jobType, Payload: payload}
}

func TestJobProcessorSyncPersistsCheckpoint(t *testing.T) {
	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, checkpoint string, handler func([]*Identity, string) error) error {
			// First page, then a terminal page carrying the delta link.
			if err := handler([]*Identity{{ExternalID: "u1"}}, "page-2"); err != nil {
				return err
			}
			return handler([]*Identity{}, "delta-link-final")
		},
	}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{})
	ctx := context.Background()
	ws := uuid.New()
	row, err := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	job := makeJob(t, svc, ws, row.ID, JobTypeSyncIdentities, nil, "")
	if err := proc.Process(ctx, job); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if mock.SyncIdentitiesCalls != 1 {
		t.Errorf("SyncIdentities called %d times, want 1", mock.SyncIdentitiesCalls)
	}

	// The delta link should be persisted for the next incremental run.
	link, err := proc.syncState.Load(ctx, ws, row.ID, "")
	if err != nil {
		t.Fatalf("Load checkpoint: %v", err)
	}
	if link != "delta-link-final" {
		t.Errorf("persisted checkpoint = %q, want delta-link-final", link)
	}
	// last_synced_at should be stamped.
	got, _ := svc.Get(ctx, ws, row.ID)
	if got.LastSyncedAt == nil {
		t.Error("last_synced_at was not stamped")
	}
}

func TestJobProcessorSyncResumesFromCheckpoint(t *testing.T) {
	var seenCheckpoint string
	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, checkpoint string, handler func([]*Identity, string) error) error {
			seenCheckpoint = checkpoint
			return handler([]*Identity{}, checkpoint)
		},
	}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{})
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})

	// Seed an existing checkpoint.
	if err := proc.syncState.Save(ctx, ws, row.ID, "", "existing-delta"); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	job := makeJob(t, svc, ws, row.ID, JobTypeSyncIdentities, nil, "")
	if err := proc.Process(ctx, job); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if seenCheckpoint != "existing-delta" {
		t.Errorf("connector resumed from %q, want existing-delta", seenCheckpoint)
	}
}

func TestJobProcessorProvisionAndRevoke(t *testing.T) {
	mock := &MockAccessConnector{}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{})
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})
	grant := &AccessGrant{UserExternalID: "u1", ResourceExternalID: "r1", Role: "viewer"}

	if err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeProvision, grant, "")); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if mock.ProvisionAccessCalls != 1 {
		t.Errorf("ProvisionAccess called %d times, want 1", mock.ProvisionAccessCalls)
	}
	if err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeRevoke, grant, "")); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if mock.RevokeAccessCalls != 1 {
		t.Errorf("RevokeAccess called %d times, want 1", mock.RevokeAccessCalls)
	}
}

func TestJobProcessorProvisionMissingGrant(t *testing.T) {
	SwapConnector(t, "test-provider", &MockAccessConnector{})
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{})
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})

	if err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeProvision, nil, "")); err == nil {
		t.Error("provision job without grant should error")
	}
}

func TestJobProcessorPropagatesConnectorError(t *testing.T) {
	syncErr := errors.New("provider 500")
	mock := &MockAccessConnector{
		FuncSyncIdentities: func(context.Context, map[string]interface{}, map[string]interface{}, string, func([]*Identity, string) error) error {
			return syncErr
		},
	}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{})
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})

	err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeSyncIdentities, nil, ""))
	if !errors.Is(err, syncErr) {
		t.Errorf("Process err = %v, want wrapped %v", err, syncErr)
	}
}

func TestJobProcessorUnknownConnectorRow(t *testing.T) {
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{})
	ctx := context.Background()

	job := makeJob(t, svc, uuid.New(), uuid.New(), JobTypeSyncIdentities, nil, "")
	if err := proc.Process(ctx, job); !errors.Is(err, ErrConnectorRowNotFound) {
		t.Errorf("Process for missing row err = %v, want ErrConnectorRowNotFound", err)
	}
}

// stubGate is a programmable HibernationGate for the gate-honouring tests.
type stubGate struct {
	run  bool
	err  error
	seen []uuid.UUID
}

func (g *stubGate) ShouldRunPeriodic(_ context.Context, ws uuid.UUID) (bool, error) {
	g.seen = append(g.seen, ws)
	return g.run, g.err
}

// TestJobProcessorSkipsDormantSync proves the connector worker DEFERS a periodic
// identity sync for a confidently-dormant tenant: the connector is never
// invoked, the skip observer fires once, and the job is acked (nil error) so it
// is not retried.
func TestJobProcessorSkipsDormantSync(t *testing.T) {
	mock := &MockAccessConnector{}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	skips := 0
	gate := &stubGate{run: false}
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{}).
		WithHibernationGate(gate, func() { skips++ })
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})

	if err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeSyncIdentities, nil, "")); err != nil {
		t.Fatalf("Process (dormant) = %v, want nil (deferred, acked)", err)
	}
	if mock.SyncIdentitiesCalls != 0 {
		t.Errorf("SyncIdentities called %d times for dormant tenant, want 0", mock.SyncIdentitiesCalls)
	}
	if skips != 1 {
		t.Errorf("skip observer fired %d times, want 1", skips)
	}
	if len(gate.seen) != 1 || gate.seen[0] != ws {
		t.Errorf("gate consulted with %v, want one call for %s", gate.seen, ws)
	}
}

// TestJobProcessorRunsActiveSync proves an active (gate=run) tenant's sync runs
// normally and the skip observer does NOT fire.
func TestJobProcessorRunsActiveSync(t *testing.T) {
	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*Identity, string) error) error {
			return handler([]*Identity{}, "delta")
		},
	}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	skips := 0
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{}).
		WithHibernationGate(&stubGate{run: true}, func() { skips++ })
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})

	if err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeSyncIdentities, nil, "")); err != nil {
		t.Fatalf("Process (active) = %v", err)
	}
	if mock.SyncIdentitiesCalls != 1 {
		t.Errorf("SyncIdentities called %d times for active tenant, want 1", mock.SyncIdentitiesCalls)
	}
	if skips != 0 {
		t.Errorf("skip observer fired %d times for active tenant, want 0", skips)
	}
}

// TestJobProcessorFailOpenOnGateError proves the FAIL-OPEN contract: a gate
// error must NEVER defer real work — the sync runs and is not counted skipped.
func TestJobProcessorFailOpenOnGateError(t *testing.T) {
	mock := &MockAccessConnector{
		FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*Identity, string) error) error {
			return handler([]*Identity{}, "delta")
		},
	}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	skips := 0
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{}).
		WithHibernationGate(&stubGate{run: false, err: errors.New("classify boom")}, func() { skips++ })
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})

	if err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeSyncIdentities, nil, "")); err != nil {
		t.Fatalf("Process (gate error) = %v, want nil (fail-open ran)", err)
	}
	if mock.SyncIdentitiesCalls != 1 {
		t.Errorf("SyncIdentities called %d times on gate error, want 1 (fail-open)", mock.SyncIdentitiesCalls)
	}
	if skips != 0 {
		t.Errorf("skip observer fired %d times on gate error, want 0", skips)
	}
}

// TestJobProcessorGateIgnoresOnDemandJobs proves the gate is consulted ONLY for
// periodic sync: provision/revoke are on-demand JML actions and must run even
// for a dormant tenant.
func TestJobProcessorGateIgnoresOnDemandJobs(t *testing.T) {
	mock := &MockAccessConnector{}
	SwapConnector(t, "test-provider", mock)
	db := newTestDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil)
	gate := &stubGate{run: false} // dormant: would skip a sync
	proc := NewConnectorJobProcessor(db, PassthroughEncryptor{}).
		WithHibernationGate(gate, func() {})
	ctx := context.Background()
	ws := uuid.New()
	row, _ := svc.Create(ctx, CreateConnectorInput{WorkspaceID: ws, Provider: "test-provider"})
	grant := &AccessGrant{UserExternalID: "u1", ResourceExternalID: "r1", Role: "viewer"}

	if err := proc.Process(ctx, makeJob(t, svc, ws, row.ID, JobTypeProvision, grant, "")); err != nil {
		t.Fatalf("provision (dormant) = %v, want it to run regardless of gate", err)
	}
	if mock.ProvisionAccessCalls != 1 {
		t.Errorf("ProvisionAccess called %d times for dormant tenant, want 1 (on-demand never gated)", mock.ProvisionAccessCalls)
	}
	if len(gate.seen) != 0 {
		t.Errorf("gate consulted %d times for provision, want 0 (on-demand never gated)", len(gate.seen))
	}
}
