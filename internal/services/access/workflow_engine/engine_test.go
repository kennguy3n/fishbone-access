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

// transitionFailRequests wraps the real request service and fails the
// requested→approved transition, leaving every other call (lock, read, create,
// other transitions) delegated. It lets a test assert that the approval-decision
// write and the request-state transition commit (or roll back) atomically.
type transitionFailRequests struct {
	requestService
	failApprove bool
}

func (w transitionFailRequests) TransitionInTx(ctx context.Context, tx *gorm.DB, workspaceID, requestID uuid.UUID, to lifecycle.RequestState, actor, reason string) (*models.AccessRequest, error) {
	if w.failApprove && to == lifecycle.StateApproved {
		return nil, errors.New("simulated transition failure")
	}
	return w.requestService.TransitionInTx(ctx, tx, workspaceID, requestID, to, actor, reason)
}

// TestApprove_DecisionAndTransitionAreAtomic asserts the decision write and the
// request transition share one transaction: when the transition fails the
// approval decision rolls back with it (no stray decision row) and nothing is
// provisioned. Recording the decision and the state change in the same tx (under
// the request row lock) is what makes Approve a single serializable unit, which
// is the property that closes the Approve/Deny race window.
func TestApprove_DecisionAndTransitionAreAtomic(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	reqSvc := lifecycle.NewAccessRequestService(db)
	store := NewApprovalStore(db)
	eng, err := NewEngine(Deps{
		Requests:  transitionFailRequests{requestService: reqSvc, failApprove: true},
		Workflow:  lifecycle.NewWorkflowService(reqSvc),
		Approvals: store,
		Queue:     q,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// nil AI → medium → manager_approval lane (required = 1 approval).
	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws, RequesterID: "alice", ResourceRef: "repo:payments", Role: "writer",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	reqID := res.Request.ID

	if _, err := eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "mgr-1"}); err == nil {
		t.Fatalf("expected the transition failure to surface")
	}

	// The decision must have rolled back with the failed transition.
	decisions, err := store.Decisions(context.Background(), ws, reqID)
	if err != nil {
		t.Fatalf("Decisions: %v", err)
	}
	if len(decisions) != 0 {
		t.Fatalf("approval decision must roll back with the failed transition; got %d rows", len(decisions))
	}
	// Request stays requested; nothing provisioned.
	got, err := reqSvc.GetRequest(context.Background(), ws, reqID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.State != lifecycle.StateRequested {
		t.Fatalf("request must remain requested after a failed approval, got %q", got.State)
	}
	if n := len(q.typed(JobTypeProvisionRequest)); n != 0 {
		t.Fatalf("a failed approval must not enqueue provisioning; got %d", n)
	}
}

// TestDeny_BlocksManagerLaneApproval proves a single deny is terminal even in
// the manager lane where one approval would otherwise satisfy the chain: once a
// deny is recorded, a subsequent (and count-sufficient) approval must not flip
// the request to approved, and the deny stays recorded for audit.
func TestDeny_BlocksManagerLaneApproval(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	eng := realEngine(t, db, q)

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws, RequesterID: "alice", ResourceRef: "repo:payments", Role: "writer",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	reqID := res.Request.ID

	if err := eng.Deny(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "mgr-1", Reason: "policy"}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	ar, err := eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "mgr-2"})
	if err != nil {
		t.Fatalf("Approve after deny: %v", err)
	}
	if ar.Approved || !ar.Chain.Rejected {
		t.Fatalf("a recorded deny must keep the chain rejected, got %+v", ar.Chain)
	}
	if n := len(q.typed(JobTypeProvisionRequest)); n != 0 {
		t.Fatalf("a denied request must never provision; got %d", n)
	}
	got, err := eng.requests.GetRequest(context.Background(), ws, reqID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.State != lifecycle.StateDenied {
		t.Fatalf("request must be denied, got %q", got.State)
	}
}

// TestApproveThenDeny_RecordsDenyForAudit covers the legitimate ordering where
// an approval completes first: a deny arriving afterward is a no-op on the
// (already terminal) request state but is still persisted for the audit trail.
func TestApproveThenDeny_RecordsDenyForAudit(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	q := &fakeQueue{}
	store := NewApprovalStore(db)
	reqSvc := lifecycle.NewAccessRequestService(db)
	eng, err := NewEngine(Deps{
		Requests:  reqSvc,
		Workflow:  lifecycle.NewWorkflowService(reqSvc),
		Approvals: store,
		Queue:     q,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	res, err := eng.SubmitRequest(context.Background(), SubmitInput{
		WorkspaceID: ws, RequesterID: "alice", ResourceRef: "repo:payments", Role: "writer",
	})
	if err != nil {
		t.Fatalf("SubmitRequest: %v", err)
	}
	reqID := res.Request.ID

	ar, err := eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "mgr-1"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !ar.Approved || ar.ProvisionJobID == "" {
		t.Fatalf("manager-lane approval should satisfy + provision, got %+v", ar)
	}

	// A deny arriving after approval committed is a no-op on state, not an error.
	if err := eng.Deny(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "mgr-2", Reason: "too late"}); err != nil {
		t.Fatalf("late Deny must not error: %v", err)
	}
	got, err := reqSvc.GetRequest(context.Background(), ws, reqID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.State != lifecycle.StateApproved {
		t.Fatalf("request approved before the deny must stay approved, got %q", got.State)
	}
	// The late deny is still recorded for audit.
	decisions, err := store.Decisions(context.Background(), ws, reqID)
	if err != nil {
		t.Fatalf("Decisions: %v", err)
	}
	var sawDeny bool
	for _, d := range decisions {
		if d.Decision == ApprovalDecisionDeny && d.Approver == "mgr-2" {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatalf("the late deny must be recorded for audit; decisions=%+v", decisions)
	}
	if n := len(q.typed(JobTypeProvisionRequest)); n != 1 {
		t.Fatalf("exactly one provisioning job expected, got %d", n)
	}
}

// TestApproveDenyConcurrentStayConsistent fires Approve and Deny at the same
// manager-lane request concurrently, across many fresh requests, and asserts the
// committed request state and the provisioning side effect never disagree. Both
// Approve and Deny take the request row lock BEFORE recording their decision and
// run record→evaluate→transition as one transaction, so they serialize: the
// winner drives the request to a single terminal state and the loser observes it
// and no-ops (a late deny is audit-only; a deny that wins blocks the approval).
// The invariant checked is the one the pre-fix code could violate: a request is
// provisioned IFF it is approved, and a denied request is never provisioned. Run
// under `go test -race` this also guards against data races in the new tx path.
func TestApproveDenyConcurrentStayConsistent(t *testing.T) {
	db := newTestDB(t)
	// Shared in-memory SQLite is per-connection; pin to one connection so every
	// goroutine sees the same data and writes serialize on SQLite's global write
	// lock (the stand-in for the Postgres FOR UPDATE row lock this is about).
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	ws := seedWorkspace(t, db, "acme")

	const iterations = 40
	for i := 0; i < iterations; i++ {
		q := &fakeQueue{}
		eng := realEngine(t, db, q)
		res, err := eng.SubmitRequest(context.Background(), SubmitInput{
			WorkspaceID: ws, RequesterID: "alice", ResourceRef: "repo:payments", Role: "writer",
		})
		if err != nil {
			t.Fatalf("iter %d SubmitRequest: %v", i, err)
		}
		reqID := res.Request.ID

		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			if _, err := eng.Approve(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "mgr-1"}); err != nil {
				t.Errorf("iter %d Approve: %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := eng.Deny(context.Background(), ApproveInput{WorkspaceID: ws, RequestID: reqID, Approver: "mgr-2"}); err != nil {
				t.Errorf("iter %d Deny: %v", i, err)
			}
		}()
		close(start)
		wg.Wait()

		got, err := eng.requests.GetRequest(context.Background(), ws, reqID)
		if err != nil {
			t.Fatalf("iter %d GetRequest: %v", i, err)
		}
		provisioned := len(q.typed(JobTypeProvisionRequest))
		switch got.State {
		case lifecycle.StateApproved:
			if provisioned != 1 {
				t.Fatalf("iter %d approved request must provision exactly once, got %d", i, provisioned)
			}
		case lifecycle.StateDenied:
			if provisioned != 0 {
				t.Fatalf("iter %d denied request must never provision, got %d", i, provisioned)
			}
		default:
			t.Fatalf("iter %d request must reach a terminal decision, got %q", i, got.State)
		}
	}
}
