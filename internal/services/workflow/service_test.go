package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

func svcTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return db
}

func seedWS(t *testing.T, db *gorm.DB, name string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: name, IAMCoreTenantID: name, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

const (
	joinerDef = `{"kind":"joiner","trigger":"manual","steps":[{"type":"notify","channel":"email","message":"welcome"}]}`
	leaverDef = `{"kind":"leaver","trigger":"manual","steps":[{"type":"run_kill_switch"}]}`
)

func mustCreate(t *testing.T, s *Service, ws uuid.UUID, name, def string) *models.Workflow {
	t.Helper()
	wf, err := s.Create(context.Background(), CreateInput{WorkspaceID: ws, Name: name, Definition: json.RawMessage(def), Actor: "admin"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return wf
}

func sampleSubject() Subject { return Subject{ExternalID: "u1", Department: "Sales"} }

func TestService_CreateGetList(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws := seedWS(t, db, "acme")

	wf := mustCreate(t, s, ws, "onboarding", joinerDef)
	if wf.State != StateDraft || wf.Version != 1 {
		t.Fatalf("new workflow should be draft v1: %+v", wf)
	}
	got, err := s.Get(context.Background(), ws, wf.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "onboarding" {
		t.Fatalf("name = %q", got.Name)
	}
	list, err := s.List(context.Background(), ws)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
}

func TestService_CreateRejectsInvalidDoc(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws := seedWS(t, db, "acme")
	_, err := s.Create(context.Background(), CreateInput{
		WorkspaceID: ws, Name: "bad", Actor: "admin",
		Definition: json.RawMessage(`{"kind":"joiner","trigger":"manual","steps":[{"type":"run_kill_switch"}]}`),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation (kill switch on joiner), got %v", err)
	}
}

func TestService_CrossTenantIsolation(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws1 := seedWS(t, db, "tenant-1")
	ws2 := seedWS(t, db, "tenant-2")

	wf := mustCreate(t, s, ws1, "ws1-flow", joinerDef)

	if _, err := s.Get(context.Background(), ws2, wf.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Get should be ErrNotFound, got %v", err)
	}
	list, err := s.List(context.Background(), ws2)
	if err != nil {
		t.Fatalf("list ws2: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ws2 must not see ws1 workflows, got %d", len(list))
	}
	// A mutation targeting ws2 + ws1's id must not touch the row either.
	if _, err := s.UpdateDraft(context.Background(), ws2, wf.ID, "hijack", json.RawMessage(joinerDef), "attacker"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant UpdateDraft should be ErrNotFound, got %v", err)
	}
}

func TestService_PublishRequiresSimulate(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws := seedWS(t, db, "acme")
	wf := mustCreate(t, s, ws, "flow", joinerDef)

	if _, err := s.Publish(context.Background(), ws, wf.ID, "admin"); !errors.Is(err, ErrNotSimulated) {
		t.Fatalf("publish before simulate should be ErrNotSimulated, got %v", err)
	}
	if _, err := s.Simulate(context.Background(), ws, wf.ID, sampleSubject()); err != nil {
		t.Fatalf("simulate: %v", err)
	}
	pub, err := s.Publish(context.Background(), ws, wf.ID, "admin")
	if err != nil {
		t.Fatalf("publish after simulate: %v", err)
	}
	if pub.State != StatePublished || pub.PublishedAt == nil {
		t.Fatalf("expected published with timestamp: %+v", pub)
	}
	// Idempotent re-publish.
	again, err := s.Publish(context.Background(), ws, wf.ID, "admin")
	if err != nil || again.State != StatePublished {
		t.Fatalf("re-publish should be idempotent, got %+v err=%v", again, err)
	}
}

func TestService_EditRelocksPublishGate(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws := seedWS(t, db, "acme")
	wf := mustCreate(t, s, ws, "flow", joinerDef)

	if _, err := s.Simulate(context.Background(), ws, wf.ID, sampleSubject()); err != nil {
		t.Fatalf("simulate: %v", err)
	}
	// Editing the draft must clear the cached simulation and re-lock publish.
	updated, err := s.UpdateDraft(context.Background(), ws, wf.ID, "", json.RawMessage(joinerDef), "admin")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(updated.DraftSimulation) != 0 {
		t.Fatal("edit must clear the cached simulation")
	}
	if _, err := s.Publish(context.Background(), ws, wf.ID, "admin"); !errors.Is(err, ErrNotSimulated) {
		t.Fatalf("publish after edit should require re-simulate, got %v", err)
	}
}

func TestService_PublishBlockedWhenSimulationFailed(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws := seedWS(t, db, "acme")
	wf := mustCreate(t, s, ws, "flow", joinerDef)

	// Defensive gate: a cached simulation whose status is "failed" must not be
	// publishable. Write one directly (a normal dry-run never fails, so this
	// guards a legacy/hand-written cache).
	failed, _ := json.Marshal(RunResult{Status: StatusFailed})
	if err := db.Model(&models.Workflow{}).Where("id = ?", wf.ID).
		Update("draft_simulation", datatypes.JSON(failed)).Error; err != nil {
		t.Fatalf("seed failed simulation: %v", err)
	}
	if _, err := s.Publish(context.Background(), ws, wf.ID, "admin"); !errors.Is(err, ErrSimulationFailed) {
		t.Fatalf("publish with failed simulation should be ErrSimulationFailed, got %v", err)
	}
}

func TestService_ArchiveStopsPublishAndRun(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws := seedWS(t, db, "acme")
	wf := mustCreate(t, s, ws, "flow", joinerDef)

	if _, err := s.Archive(context.Background(), ws, wf.ID, "admin"); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if _, err := s.Publish(context.Background(), ws, wf.ID, "admin"); !errors.Is(err, ErrNotPublishable) {
		t.Fatalf("publish archived should be ErrNotPublishable, got %v", err)
	}
	if _, err := s.Run(context.Background(), ws, wf.ID, sampleSubject(), "admin", StepDeps{}); !errors.Is(err, ErrNotRunnable) {
		t.Fatalf("run archived should be ErrNotRunnable, got %v", err)
	}
}

func TestService_RunOnlyPublishedAndRecordsRun(t *testing.T) {
	db := svcTestDB(t)
	s := NewService(db)
	ws := seedWS(t, db, "acme")
	wf := mustCreate(t, s, ws, "flow", joinerDef)

	// A draft cannot run.
	if _, err := s.Run(context.Background(), ws, wf.ID, sampleSubject(), "admin", StepDeps{}); !errors.Is(err, ErrNotRunnable) {
		t.Fatalf("run draft should be ErrNotRunnable, got %v", err)
	}

	if _, err := s.Simulate(context.Background(), ws, wf.ID, sampleSubject()); err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if _, err := s.Publish(context.Background(), ws, wf.ID, "admin"); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deps := StepDeps{Notifier: &fakeNotifier{ref: "email"}, Audit: &fakeAuditor{}}
	res, err := s.Run(context.Background(), ws, wf.ID, sampleSubject(), "admin", deps)
	if err != nil {
		t.Fatalf("run published: %v", err)
	}
	if res.Status != StatusSucceeded || res.RunID == nil {
		t.Fatalf("run result unexpected: %+v", res)
	}

	runs, err := s.ListRuns(context.Background(), ws, 0)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	if _, err := s.GetRun(context.Background(), ws, *res.RunID); err != nil {
		t.Fatalf("get run: %v", err)
	}
	// Run history is workspace-scoped.
	other := seedWS(t, db, "other")
	if _, err := s.GetRun(context.Background(), other, *res.RunID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant GetRun should be ErrNotFound, got %v", err)
	}
}
