package workflow_engine

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// enqueuedJob captures one Enqueue call for assertions.
type enqueuedJob struct {
	WorkspaceID uuid.UUID
	ConnectorID uuid.UUID
	Type        string
	Payload     []byte
}

// fakeQueue is an in-memory Enqueuer that records every job. It optionally fails
// to exercise the engine's enqueue-failure handling.
type fakeQueue struct {
	mu   sync.Mutex
	jobs []enqueuedJob
	fail error
}

func (q *fakeQueue) Enqueue(_ context.Context, workspaceID, connectorID uuid.UUID, jobType string, payload []byte) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fail != nil {
		return "", q.fail
	}
	q.jobs = append(q.jobs, enqueuedJob{WorkspaceID: workspaceID, ConnectorID: connectorID, Type: jobType, Payload: payload})
	return uuid.NewString(), nil
}

func (q *fakeQueue) typed(jobType string) []enqueuedJob {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []enqueuedJob
	for _, j := range q.jobs {
		if j.Type == jobType {
			out = append(out, j)
		}
	}
	return out
}

// fakeRouter is a workflowRouter that returns a fixed decision, used to drive the
// auto-approve submit path deterministically without a live AI agent.
type fakeRouter struct {
	decision lifecycle.WorkflowDecision
}

func (r fakeRouter) ExecuteWorkflow(_ context.Context, _ uuid.UUID, _ *models.AccessRequest, _ string) (lifecycle.WorkflowDecision, error) {
	return r.decision, nil
}

func newTestDB(t *testing.T) *gorm.DB {
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

func seedWorkspace(t *testing.T, db *gorm.DB, name string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: name, IAMCoreTenantID: name, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

// realEngine wires the engine over real lifecycle services on sqlite with a fake
// queue. ai is nil so risk assessment uses the deterministic fallback (medium).
func realEngine(t *testing.T, db *gorm.DB, q Enqueuer) *Engine {
	t.Helper()
	reqSvc := lifecycle.NewAccessRequestService(db)
	eng, err := NewEngine(Deps{
		Requests:  reqSvc,
		Workflow:  lifecycle.NewWorkflowService(reqSvc),
		AI:        nil,
		Approvals: NewApprovalStore(db),
		Queue:     q,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func TestSubmitRequest_MediumRisk_ParkedForManagerApproval(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID:   ws,
		RequesterID:   "alice",
		ResourceRef:   "repo:payments",
		Role:          "writer",
		Justification: "ship feature",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	// nil AI → fallback medium → manager_approval lane → parked, nothing provisioned.
	if res.Decision.StepType != lifecycle.WorkflowStepManagerApproval {
		t.Fatalf("step = %q, want manager_approval", res.Decision.StepType)
	}
	if res.Provisioning {
		t.Fatalf("medium-risk request must not auto-provision")
	}
	if got := len(q.typed(JobTypeProvisionRequest)); got != 0 {
		t.Fatalf("expected no provisioning jobs, got %d", got)
	}
	if res.Request.RiskLevel != "medium" {
		t.Fatalf("risk = %q, want medium", res.Request.RiskLevel)
	}
}

func TestSubmitRequest_SensitiveTag_ForcesSecurityReview(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID:  ws,
		RequesterID:  "alice",
		ResourceRef:  "db:prod",
		Role:         "admin",
		ResourceTags: []string{"sensitive"},
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	if res.Decision.StepType != lifecycle.WorkflowStepSecurityReview {
		t.Fatalf("step = %q, want security_review", res.Decision.StepType)
	}
	if RequiredApprovals(res.Decision.StepType) != 2 {
		t.Fatalf("security review must require two approvals")
	}
}

func TestSubmitRequest_AutoApprove_EnqueuesProvisioning(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	reqSvc := lifecycle.NewAccessRequestService(db)
	eng, err := NewEngine(Deps{
		Requests:  reqSvc,
		Workflow:  fakeRouter{decision: lifecycle.WorkflowDecision{StepType: lifecycle.WorkflowStepAutoApprove, Approved: true}},
		Approvals: NewApprovalStore(db),
		Queue:     q,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws,
		RequesterID: "alice",
		ResourceRef: "wiki:read",
		Role:        "reader",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	if !res.Provisioning || res.ProvisionJobID == "" {
		t.Fatalf("auto-approved request must enqueue provisioning, got %+v", res)
	}
	jobs := q.typed(JobTypeProvisionRequest)
	if len(jobs) != 1 {
		t.Fatalf("want 1 provisioning job, got %d", len(jobs))
	}
	if jobs[0].WorkspaceID != ws {
		t.Fatalf("provisioning job workspace = %s, want %s", jobs[0].WorkspaceID, ws)
	}
}

func TestApprove_ManagerLane_OneApprovalProvisions(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws, RequesterID: "alice", ResourceRef: "repo:x", Role: "writer",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	reqID := res.Request.ID

	ar, err := eng.Approve(context.Background(), ApproveInput{
		WorkspaceID: ws, RequestID: reqID, Approver: "manager-bob", Reason: "ok",
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !ar.Approved || ar.ProvisionJobID == "" {
		t.Fatalf("single manager approval should satisfy + provision, got %+v", ar)
	}
	if got := len(q.typed(JobTypeProvisionRequest)); got != 1 {
		t.Fatalf("want 1 provisioning job, got %d", got)
	}

	// Idempotency: re-approving an already-approved request must not enqueue a
	// second provisioning job.
	if _, err := eng.Approve(context.Background(), ApproveInput{
		WorkspaceID: ws, RequestID: reqID, Approver: "manager-bob", Reason: "ok again",
	}); err != nil {
		t.Fatalf("re-Approve: %v", err)
	}
	if got := len(q.typed(JobTypeProvisionRequest)); got != 1 {
		t.Fatalf("re-approval must not double-provision; got %d jobs", got)
	}
}

func TestApprove_SecurityLane_RequiresTwoDistinctApprovers(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws, RequesterID: "alice", ResourceRef: "db:prod", Role: "admin",
		ResourceTags: []string{"sensitive"},
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	reqID := res.Request.ID

	// First approval: not satisfied.
	ar, err := eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "sec-1"})
	if err != nil {
		t.Fatalf("Approve#1: %v", err)
	}
	if ar.Approved {
		t.Fatalf("one approval must not satisfy a security-review chain")
	}

	// Same approver again: still not satisfied (distinct-approver rule).
	ar, err = eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "sec-1"})
	if err != nil {
		t.Fatalf("Approve#1-dup: %v", err)
	}
	if ar.Approved {
		t.Fatalf("duplicate approver must not satisfy four-eyes")
	}
	if got := len(q.typed(JobTypeProvisionRequest)); got != 0 {
		t.Fatalf("must not provision before two distinct approvals; got %d", got)
	}

	// Second distinct approver: satisfied → approved + provisioned.
	ar, err = eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "sec-2"})
	if err != nil {
		t.Fatalf("Approve#2: %v", err)
	}
	if !ar.Approved || ar.ProvisionJobID == "" {
		t.Fatalf("two distinct approvals should satisfy + provision, got %+v", ar)
	}
	if got := len(q.typed(JobTypeProvisionRequest)); got != 1 {
		t.Fatalf("want exactly 1 provisioning job, got %d", got)
	}
}

func TestDeny_RejectsAndBlocksLaterApproval(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws, RequesterID: "alice", ResourceRef: "db:prod", Role: "admin",
		ResourceTags: []string{"sensitive"},
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	reqID := res.Request.ID

	if err := eng.Deny(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "sec-1", Reason: "nope"}); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	// A later approval cannot move a denied request (state left StateRequested),
	// and must not provision.
	ar, err := eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "sec-2"})
	if err != nil {
		t.Fatalf("Approve after deny: %v", err)
	}
	// The chain is flagged rejected, so Satisfied() is false regardless of count.
	if ar.Approved {
		t.Fatalf("approval after a deny must not satisfy the chain")
	}
	if got := len(q.typed(JobTypeProvisionRequest)); got != 0 {
		t.Fatalf("denied request must never provision; got %d", got)
	}
}

func TestIngestSCIMEvent_EnqueuesJMLJob(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	id, err := eng.IngestSCIMEvent(context.Background(), ws, lifecycle.SCIMEvent{
		Method:         "POST",
		UserExternalID: "u-1",
	})
	if err != nil {
		t.Fatalf("IngestSCIMEvent: %v", err)
	}
	if id == "" {
		t.Fatalf("expected job id")
	}
	if got := len(q.typed(JobTypeJMLEvent)); got != 1 {
		t.Fatalf("want 1 jml job, got %d", got)
	}
}

func TestScheduleReviewSweep_EnqueuesReviewJob(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	if _, err := eng.ScheduleReviewSweep(context.Background(), ws, "", "scheduler", ""); err != nil {
		t.Fatalf("ScheduleReviewSweep: %v", err)
	}
	if got := len(q.typed(JobTypeReviewSweep)); got != 1 {
		t.Fatalf("want 1 review job, got %d", got)
	}
}

func TestSubmitRequest_EnqueueFailureSurfaced(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{fail: errors.New("queue down")}
	reqSvc := lifecycle.NewAccessRequestService(db)
	eng, err := NewEngine(Deps{
		Requests:  reqSvc,
		Workflow:  fakeRouter{decision: lifecycle.WorkflowDecision{StepType: lifecycle.WorkflowStepAutoApprove, Approved: true}},
		Approvals: NewApprovalStore(db),
		Queue:     q,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws, RequesterID: "alice", ResourceRef: "wiki:read", Role: "reader",
	})
	if err == nil {
		t.Fatalf("expected enqueue failure to surface")
	}
	// The request is still created + approved in the FSM even though enqueue failed.
	if res == nil || res.Request == nil {
		t.Fatalf("expected the approved request to be returned alongside the error")
	}
}
