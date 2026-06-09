package workflow_engine

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/workflow"
	"github.com/kennguy3n/fishbone-access/internal/workers"
)

type fakeJML struct {
	class  string
	leaver *lifecycle.LeaverResult
	err    error
	calls  int
}

func (f *fakeJML) HandleEvent(_ context.Context, _ uuid.UUID, _ lifecycle.SCIMEvent) (string, *lifecycle.LeaverResult, error) {
	f.calls++
	return f.class, f.leaver, f.err
}

type fakeProvisioner struct {
	err   error
	calls int
}

func (f *fakeProvisioner) Provision(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ string) (*models.AccessGrant, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &models.AccessGrant{}, nil
}

type submittedDecision struct {
	itemID   uuid.UUID
	decision string
}

type fakeReviews struct {
	mu        sync.Mutex
	review    *models.AccessReview
	items     []models.AccessReviewItem
	startErr  error
	submitted []submittedDecision
	completed bool
	startCnt  int
}

func (f *fakeReviews) StartCampaign(_ context.Context, ws uuid.UUID, name, _ string) (*models.AccessReview, int, error) {
	f.startCnt++
	if f.startErr != nil {
		return nil, 0, f.startErr
	}
	if f.review == nil {
		f.review = &models.AccessReview{Base: models.Base{ID: uuid.New()}, WorkspaceID: ws, Name: name}
	}
	return f.review, len(f.items), nil
}

func (f *fakeReviews) ListItems(_ context.Context, _ uuid.UUID, _ uuid.UUID) ([]models.AccessReviewItem, error) {
	return f.items, nil
}

func (f *fakeReviews) SubmitDecision(_ context.Context, _ uuid.UUID, _ uuid.UUID, itemID uuid.UUID, decision, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitted = append(f.submitted, submittedDecision{itemID: itemID, decision: decision})
	return nil
}

func (f *fakeReviews) CompleteCampaign(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ string) (lifecycle.ReviewReport, error) {
	f.completed = true
	return lifecycle.ReviewReport{}, nil
}

type fakeGrants struct {
	grant *models.AccessGrant
	err   error
}

func (f *fakeGrants) GetGrant(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*models.AccessGrant, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.grant, nil
}

type fakeWorkflows struct {
	result *workflow.RunResult
	err    error
	calls  int
}

func (f *fakeWorkflows) Run(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ workflow.Subject, _ string, _ workflow.StepDeps) (*workflow.RunResult, error) {
	f.calls++
	return f.result, f.err
}

func newProcessor(t *testing.T, d ProcessorDeps) *JobProcessor {
	t.Helper()
	p, err := NewJobProcessor(d)
	if err != nil {
		t.Fatalf("NewJobProcessor: %v", err)
	}
	return p
}

func baseDeps() ProcessorDeps {
	return ProcessorDeps{
		JML:         &fakeJML{class: "joiner"},
		Provisioner: &fakeProvisioner{},
		Reviews:     &fakeReviews{},
		Grants:      &fakeGrants{grant: &models.AccessGrant{}},
		Workflows:   &fakeWorkflows{result: &workflow.RunResult{Status: workflow.StatusSucceeded}},
		WorkflowDeps: func(uuid.UUID, string) workflow.StepDeps {
			return workflow.StepDeps{}
		},
	}
}

func TestProcess_UnknownTypeErrors(t *testing.T) {
	p := newProcessor(t, baseDeps())
	err := p.Process(context.Background(), workers.Job{ID: "j1", Type: "connector.provision"})
	if err == nil {
		t.Fatalf("expected error for unknown job type")
	}
}

func TestHandleWorkflowRun_Success(t *testing.T) {
	wf := &fakeWorkflows{result: &workflow.RunResult{Status: workflow.StatusSucceeded}}
	d := baseDeps()
	d.Workflows = wf
	var builtWS uuid.UUID
	d.WorkflowDeps = func(ws uuid.UUID, _ string) workflow.StepDeps {
		builtWS = ws
		return workflow.StepDeps{}
	}
	p := newProcessor(t, d)

	ws := uuid.New()
	payload, _ := json.Marshal(workflowRunPayload{
		WorkspaceID: ws.String(),
		WorkflowID:  uuid.NewString(),
		Subject:     workflow.Subject{ExternalID: "u1"},
		Actor:       "engine",
	})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeWorkflowRun, Payload: payload}); err != nil {
		t.Fatalf("Process workflow-run: %v", err)
	}
	if wf.calls != 1 {
		t.Fatalf("Run calls = %d, want 1", wf.calls)
	}
	if builtWS != ws {
		t.Fatalf("step deps built for %s, want %s", builtWS, ws)
	}
}

func TestHandleWorkflowRun_StepFailuresRetries(t *testing.T) {
	d := baseDeps()
	d.Workflows = &fakeWorkflows{result: &workflow.RunResult{Status: workflow.StatusFailed}}
	p := newProcessor(t, d)

	payload, _ := json.Marshal(workflowRunPayload{
		WorkspaceID: uuid.NewString(),
		WorkflowID:  uuid.NewString(),
		Subject:     workflow.Subject{ExternalID: "u1"},
	})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeWorkflowRun, Payload: payload}); err == nil {
		t.Fatal("expected error so the job retries when a step failed")
	}
}

func TestHandleJMLEvent_Success(t *testing.T) {
	jml := &fakeJML{class: "joiner"}
	d := baseDeps()
	d.JML = jml
	p := newProcessor(t, d)

	payload, _ := json.Marshal(jmlEventPayload{WorkspaceID: uuid.NewString(), Event: lifecycle.SCIMEvent{Method: "POST", UserExternalID: "u1"}})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeJMLEvent, Payload: payload}); err != nil {
		t.Fatalf("Process jml: %v", err)
	}
	if jml.calls != 1 {
		t.Fatalf("HandleEvent calls = %d, want 1", jml.calls)
	}
}

func TestHandleJMLEvent_LeaverErroredRetries(t *testing.T) {
	d := baseDeps()
	d.JML = &fakeJML{class: "leaver", leaver: &lifecycle.LeaverResult{UserExternalID: "u1", Errored: true}}
	p := newProcessor(t, d)

	payload, _ := json.Marshal(jmlEventPayload{WorkspaceID: uuid.NewString(), Event: lifecycle.SCIMEvent{Method: "DELETE", UserExternalID: "u1"}})
	err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeJMLEvent, Payload: payload})
	if err == nil {
		t.Fatalf("a leaver kill switch with layer failures must return an error so the job retries")
	}
}

func TestHandleJMLEvent_BadWorkspaceErrors(t *testing.T) {
	p := newProcessor(t, baseDeps())
	payload, _ := json.Marshal(jmlEventPayload{WorkspaceID: "not-a-uuid", Event: lifecycle.SCIMEvent{Method: "POST"}})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeJMLEvent, Payload: payload}); err == nil {
		t.Fatalf("expected invalid workspace_id error")
	}
}

func TestHandleProvision_Success(t *testing.T) {
	prov := &fakeProvisioner{}
	d := baseDeps()
	d.Provisioner = prov
	p := newProcessor(t, d)

	payload, _ := json.Marshal(provisionRequestPayload{WorkspaceID: uuid.NewString(), RequestID: uuid.NewString(), Actor: "x"})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeProvisionRequest, Payload: payload}); err != nil {
		t.Fatalf("Process provision: %v", err)
	}
	if prov.calls != 1 {
		t.Fatalf("Provision calls = %d, want 1", prov.calls)
	}
}

func TestHandleProvision_ErrorPropagates(t *testing.T) {
	d := baseDeps()
	d.Provisioner = &fakeProvisioner{err: errors.New("connector down")}
	p := newProcessor(t, d)

	payload, _ := json.Marshal(provisionRequestPayload{WorkspaceID: uuid.NewString(), RequestID: uuid.NewString()})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeProvisionRequest, Payload: payload}); err == nil {
		t.Fatalf("expected provisioning error to propagate so the job retries/dead-letters")
	}
}

func TestHandleReviewSweep_EscalatesWhenAIDown(t *testing.T) {
	item1 := models.AccessReviewItem{Base: models.Base{ID: uuid.New()}, GrantID: uuid.New()}
	item2 := models.AccessReviewItem{Base: models.Base{ID: uuid.New()}, GrantID: uuid.New()}
	reviews := &fakeReviews{items: []models.AccessReviewItem{item1, item2}}
	d := baseDeps()
	d.Reviews = reviews
	d.AI = nil // fallback → defer to human → escalate
	p := newProcessor(t, d)

	payload, _ := json.Marshal(reviewSweepPayload{WorkspaceID: uuid.NewString(), CampaignName: "c", Actor: "sched"})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeReviewSweep, Payload: payload}); err != nil {
		t.Fatalf("Process review sweep: %v", err)
	}
	if !reviews.completed {
		t.Fatalf("campaign must be completed")
	}
	if len(reviews.submitted) != 2 {
		t.Fatalf("expected a decision per item, got %d", len(reviews.submitted))
	}
	for _, s := range reviews.submitted {
		if s.decision != lifecycle.ReviewDecisionEscalate {
			t.Fatalf("AI-down sweep must escalate (never auto-certify/revoke); got %q", s.decision)
		}
	}
}

func TestHandleReviewSweep_GrantLookupFailureLeavesPending(t *testing.T) {
	item := models.AccessReviewItem{Base: models.Base{ID: uuid.New()}, GrantID: uuid.New()}
	reviews := &fakeReviews{items: []models.AccessReviewItem{item}}
	d := baseDeps()
	d.Reviews = reviews
	d.Grants = &fakeGrants{err: errors.New("not found")}
	p := newProcessor(t, d)

	payload, _ := json.Marshal(reviewSweepPayload{WorkspaceID: uuid.NewString(), CampaignName: "c"})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeReviewSweep, Payload: payload}); err != nil {
		t.Fatalf("a per-item grant lookup failure must not fail the whole sweep: %v", err)
	}
	if len(reviews.submitted) != 0 {
		t.Fatalf("item with unreadable grant must be left pending, got %d decisions", len(reviews.submitted))
	}
	if !reviews.completed {
		t.Fatalf("campaign should still complete")
	}
}

func TestHandleReviewSweep_StartFailureRetries(t *testing.T) {
	d := baseDeps()
	d.Reviews = &fakeReviews{startErr: errors.New("db down")}
	p := newProcessor(t, d)

	payload, _ := json.Marshal(reviewSweepPayload{WorkspaceID: uuid.NewString(), CampaignName: "c"})
	if err := p.Process(context.Background(), workers.Job{ID: "j", Type: JobTypeReviewSweep, Payload: payload}); err == nil {
		t.Fatalf("StartCampaign failure must fail the job so it retries")
	}
}
