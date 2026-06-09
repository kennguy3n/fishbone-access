package workflow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
)

// --- fakes for the executor's side-effecting dependencies ---

type fakeGranter struct {
	calls int
	ref   string
	err   error
	got   []GrantInput
}

func (f *fakeGranter) GrantRole(_ context.Context, in GrantInput, _ string) (string, error) {
	f.calls++
	f.got = append(f.got, in)
	return f.ref, f.err
}

type fakeApprover struct {
	calls int
	ref   string
	err   error
}

func (f *fakeApprover) RequestApproval(_ context.Context, _ GrantInput, _, _ string) (string, error) {
	f.calls++
	return f.ref, f.err
}

type fakeReviewer struct {
	calls int
	ref   string
	err   error
}

func (f *fakeReviewer) StartReview(_ context.Context, _, _ string) (string, error) {
	f.calls++
	return f.ref, f.err
}

type fakeNotifier struct {
	calls int
	ref   string
	err   error
}

func (f *fakeNotifier) Notify(_ context.Context, _ Subject, _, _, _ string) (string, error) {
	f.calls++
	return f.ref, f.err
}

type fakeKillSwitch struct {
	calls   int
	layers  []KillSwitchLayer
	errored bool
	err     error
}

func (f *fakeKillSwitch) RunKillSwitch(_ context.Context, _, _ string) ([]KillSwitchLayer, bool, error) {
	f.calls++
	return f.layers, f.errored, f.err
}

type fakeAuditor struct {
	actions []string
	err     error
}

func (f *fakeAuditor) Append(_ context.Context, action, _, _ string) error {
	f.actions = append(f.actions, action)
	return f.err
}

func execTestDB(t *testing.T) *gorm.DB {
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

func mustDoc(t *testing.T, raw string) Doc {
	t.Helper()
	doc, err := ParseDoc([]byte(raw))
	if err != nil {
		t.Fatalf("parse doc: %v", err)
	}
	return doc
}

func TestExecute_DryRunNoSideEffects(t *testing.T) {
	db := execTestDB(t)
	exec := NewExecutor(db)
	granter, notifier, ks := &fakeGranter{}, &fakeNotifier{}, &fakeKillSwitch{}
	auditor := &fakeAuditor{}

	doc := mustDoc(t, `{"kind":"leaver","trigger":"manual","steps":[
		{"type":"grant_role","connector_id":"`+testConnID+`","resource_ref":"crm","role":"viewer"},
		{"type":"notify","channel":"email","message":"bye"},
		{"type":"run_kill_switch"}
	]}`)

	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         doc,
		Subject:     Subject{ExternalID: "u1"},
		Mode:        ModeDryRun,
		Deps:        StepDeps{Grants: granter, Notifier: notifier, KillSwitch: ks, Audit: auditor},
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if res.Status != StatusPlanned {
		t.Fatalf("status = %q, want planned", res.Status)
	}
	// No dependency and no auditor may have been called.
	if granter.calls+notifier.calls+ks.calls != 0 {
		t.Fatalf("dry-run invoked deps: grant=%d notify=%d ks=%d", granter.calls, notifier.calls, ks.calls)
	}
	if len(auditor.actions) != 0 {
		t.Fatalf("dry-run wrote audit entries: %v", auditor.actions)
	}
	// The kill-switch step lists the six layers it WOULD run.
	last := res.Steps[len(res.Steps)-1]
	if len(last.Layers) != len(killSwitchLayerOrder) {
		t.Fatalf("kill-switch plan layers = %d, want %d", len(last.Layers), len(killSwitchLayerOrder))
	}
	// And no run row was persisted.
	var count int64
	db.Model(&models.WorkflowRun{}).Count(&count)
	if count != 0 {
		t.Fatalf("dry-run persisted %d runs, want 0", count)
	}
}

func TestExecute_LiveDrivesDepsAuditAndPersists(t *testing.T) {
	db := execTestDB(t)
	exec := NewExecutor(db)
	ws := uuid.New()
	granter := &fakeGranter{ref: "grant-1"}
	notifier := &fakeNotifier{ref: "email"}
	reviewer := &fakeReviewer{ref: "rev-1"}
	auditor := &fakeAuditor{}

	doc := mustDoc(t, `{"kind":"joiner","trigger":"manual","steps":[
		{"type":"grant_role","connector_id":"`+testConnID+`","resource_ref":"crm","role":"viewer"},
		{"type":"notify","channel":"email","message":"welcome"},
		{"type":"start_access_review","review_name":"new-joiner"}
	]}`)

	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: ws,
		Workflow:    &models.Workflow{Base: models.Base{ID: uuid.New()}, Version: 3},
		Doc:         doc,
		Subject:     Subject{ExternalID: "u1", Department: "Sales"},
		Mode:        ModeLive,
		Actor:       "admin@acme",
		Deps:        StepDeps{Grants: granter, Notifier: notifier, Reviews: reviewer, Audit: auditor},
	})
	if err != nil {
		t.Fatalf("live run: %v", err)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status = %q, want succeeded", res.Status)
	}
	if granter.calls != 1 || notifier.calls != 1 || reviewer.calls != 1 {
		t.Fatalf("deps not all called once: %+v %+v %+v", granter, notifier, reviewer)
	}
	if granter.got[0].ConnectorID != testConnID || granter.got[0].Role != "viewer" {
		t.Fatalf("grant input not threaded through: %+v", granter.got[0])
	}
	if len(auditor.actions) != 3 {
		t.Fatalf("audit entries = %d, want 3 (%v)", len(auditor.actions), auditor.actions)
	}
	if res.RunID == nil {
		t.Fatal("live run did not return a persisted run id")
	}
	var run models.WorkflowRun
	if err := db.First(&run, "id = ?", *res.RunID).Error; err != nil {
		t.Fatalf("load persisted run: %v", err)
	}
	if run.WorkspaceID != ws || run.Status != StatusSucceeded || run.WorkflowVersion != 3 {
		t.Fatalf("persisted run mismatch: %+v", run)
	}
}

func TestExecute_LiveRequestApprovalGate(t *testing.T) {
	exec := NewExecutor(execTestDB(t))
	approver := &fakeApprover{ref: "req-1"}
	auditor := &fakeAuditor{}
	doc := mustDoc(t, `{"kind":"joiner","trigger":"manual","steps":[
		{"type":"request_approval","connector_id":"`+testConnID+`","resource_ref":"prod-db","role":"admin","approver_role":"manager"}
	]}`)

	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         doc,
		Subject:     Subject{ExternalID: "u1"},
		Mode:        ModeLive,
		Deps:        StepDeps{Approvals: approver, Audit: auditor},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if approver.calls != 1 {
		t.Fatalf("approver calls = %d, want 1", approver.calls)
	}
	if res.Status != StatusSucceeded || res.Steps[0].Ref != "req-1" {
		t.Fatalf("unexpected approval outcome: %+v", res.Steps[0])
	}
}

func TestExecute_LiveConditionsNotMatchedSkips(t *testing.T) {
	db := execTestDB(t)
	exec := NewExecutor(db)
	granter := &fakeGranter{}
	auditor := &fakeAuditor{}

	doc := mustDoc(t, `{"kind":"joiner","trigger":"manual",
		"conditions":[{"attribute":"department","operator":"eq","values":["Finance"]}],
		"steps":[{"type":"grant_role","connector_id":"`+testConnID+`","resource_ref":"crm","role":"viewer"}]}`)

	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         doc,
		Subject:     Subject{ExternalID: "u1", Department: "Sales"},
		Mode:        ModeLive,
		Deps:        StepDeps{Grants: granter, Audit: auditor},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Matched {
		t.Fatal("expected subject not to match")
	}
	if res.Status != StatusSkipped {
		t.Fatalf("status = %q, want skipped", res.Status)
	}
	if granter.calls != 0 {
		t.Fatalf("granter called %d times for non-matching subject", granter.calls)
	}
	if res.RunID != nil {
		t.Fatalf("non-matching live run persisted a run id %v, want none", res.RunID)
	}
	// A non-matching live run must not write a workflow_runs row (avoids
	// table bloat from high-frequency identity events).
	var count int64
	db.Model(&models.WorkflowRun{}).Count(&count)
	if count != 0 {
		t.Fatalf("non-matching live run persisted %d rows, want 0", count)
	}
}

func TestExecute_LiveAuditFailureAnnotatedOnPersistedRun(t *testing.T) {
	db := execTestDB(t)
	exec := NewExecutor(db)
	// The audit sink fails on every append; the step's side effect still
	// happened, so the outcome must be annotated rather than dropped — and the
	// annotation must survive into the persisted run record.
	auditor := &fakeAuditor{err: errors.New("audit store offline")}

	doc := mustDoc(t, `{"kind":"joiner","trigger":"manual","steps":[
		{"type":"notify","channel":"email","message":"welcome"}
	]}`)

	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         doc,
		Subject:     Subject{ExternalID: "u1"},
		Mode:        ModeLive,
		Deps:        StepDeps{Notifier: &fakeNotifier{ref: "email"}, Audit: auditor},
	})
	if err != nil {
		t.Fatalf("live run: %v", err)
	}
	if len(res.Steps) != 1 || !strings.Contains(res.Steps[0].Detail, "audit append failed") {
		t.Fatalf("in-memory outcome not annotated: %+v", res.Steps)
	}
	if res.RunID == nil {
		t.Fatal("live run did not persist a run id")
	}
	var run models.WorkflowRun
	if err := db.First(&run, "id = ?", *res.RunID).Error; err != nil {
		t.Fatalf("load persisted run: %v", err)
	}
	if !strings.Contains(string(run.Steps), "audit append failed") {
		t.Fatalf("persisted run lost the audit-failure annotation: %s", run.Steps)
	}
}

func TestExecute_LiveKillSwitchAllLayers(t *testing.T) {
	db := execTestDB(t)
	exec := NewExecutor(db)
	layers := make([]KillSwitchLayer, 0, len(killSwitchLayerOrder))
	for _, l := range killSwitchLayerOrder {
		layers = append(layers, KillSwitchLayer{Layer: l, Status: StatusDone})
	}
	ks := &fakeKillSwitch{layers: layers}

	doc := mustDoc(t, `{"kind":"leaver","trigger":"identity_event","steps":[{"type":"run_kill_switch"}]}`)
	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         doc,
		Subject:     Subject{ExternalID: "leaver-1"},
		Mode:        ModeLive,
		Deps:        StepDeps{KillSwitch: ks, Audit: &fakeAuditor{}},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ks.calls != 1 {
		t.Fatalf("kill switch calls = %d, want 1", ks.calls)
	}
	if res.Status != StatusSucceeded {
		t.Fatalf("status = %q, want succeeded", res.Status)
	}
	if got := len(res.Steps[0].Layers); got != len(killSwitchLayerOrder) {
		t.Fatalf("recorded layers = %d, want %d", got, len(killSwitchLayerOrder))
	}
}

func TestExecute_LiveKillSwitchMissingDepFailsClosed(t *testing.T) {
	exec := NewExecutor(execTestDB(t))
	doc := mustDoc(t, `{"kind":"leaver","trigger":"manual","steps":[{"type":"run_kill_switch"}]}`)
	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         doc,
		Subject:     Subject{ExternalID: "leaver-1"},
		Mode:        ModeLive,
		Deps:        StepDeps{Audit: &fakeAuditor{}}, // no KillSwitch wired
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("missing kill-switch dep must fail closed, got %q", res.Status)
	}
}

func TestExecute_AggregateStatusPartialAndFailed(t *testing.T) {
	exec := NewExecutor(execTestDB(t))
	twoSteps := `{"kind":"joiner","trigger":"manual","steps":[
		{"type":"grant_role","connector_id":"` + testConnID + `","resource_ref":"crm","role":"viewer"},
		{"type":"notify","channel":"email","message":"hi"}
	]}`

	// One step fails → partial.
	res, err := exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         mustDoc(t, twoSteps),
		Subject:     Subject{ExternalID: "u1"},
		Mode:        ModeLive,
		Deps: StepDeps{
			Grants:   &fakeGranter{err: errors.New("connector down")},
			Notifier: &fakeNotifier{ref: "email"},
			Audit:    &fakeAuditor{},
		},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != StatusPartial {
		t.Fatalf("status = %q, want partial", res.Status)
	}

	// Every step fails → failed.
	res, err = exec.Execute(context.Background(), RunParams{
		WorkspaceID: uuid.New(),
		Doc:         mustDoc(t, twoSteps),
		Subject:     Subject{ExternalID: "u1"},
		Mode:        ModeLive,
		Deps: StepDeps{
			Grants:   &fakeGranter{err: errors.New("connector down")},
			Notifier: &fakeNotifier{err: errors.New("smtp down")},
			Audit:    &fakeAuditor{},
		},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
}

func TestExecute_RejectsBadInput(t *testing.T) {
	exec := NewExecutor(execTestDB(t))
	doc := mustDoc(t, `{"kind":"joiner","trigger":"manual","steps":[{"type":"notify","channel":"email"}]}`)
	if _, err := exec.Execute(context.Background(), RunParams{Doc: doc, Mode: ModeLive, Subject: Subject{}}); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for empty subject, got %v", err)
	}
	if _, err := exec.Execute(context.Background(), RunParams{Doc: doc, Mode: "bogus", Subject: Subject{ExternalID: "u1"}}); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for bad mode, got %v", err)
	}
}
