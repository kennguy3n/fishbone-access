package lifecycle

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// newTestDB opens an in-memory SQLite database with the full schema migrated.
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

// seedWorkspace inserts a workspace and returns its id.
func seedWorkspace(t *testing.T, db *gorm.DB, tenant string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: tenant, IAMCoreTenantID: tenant, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

// seedConnector inserts an access connector and returns its id.
func seedConnector(t *testing.T, db *gorm.DB, workspaceID uuid.UUID, provider string) uuid.UUID {
	t.Helper()
	c := &models.AccessConnector{WorkspaceID: workspaceID, Provider: provider, Status: "active"}
	if err := db.Create(c).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	return c.ID
}

func TestTransitionTable(t *testing.T) {
	valid := []struct{ from, to RequestState }{
		{StateRequested, StateApproved},
		{StateRequested, StateDenied},
		{StateRequested, StateCancelled},
		{StateApproved, StateProvisioning},
		{StateApproved, StateCancelled},
		{StateProvisioning, StateProvisioned},
		{StateProvisioning, StateProvisionFailed},
		{StateProvisionFailed, StateProvisioning},
		{StateProvisioned, StateActive},
		{StateActive, StateRevoked},
		{StateActive, StateExpired},
	}
	for _, tc := range valid {
		if err := Transition(tc.from, tc.to); err != nil {
			t.Errorf("expected %s→%s valid, got %v", tc.from, tc.to, err)
		}
	}

	invalid := []struct{ from, to RequestState }{
		{StateRequested, StateProvisioning}, // must be approved first
		{StateApproved, StateActive},        // must provision first
		{StateRevoked, StateActive},         // terminal
		{StateDenied, StateApproved},        // terminal
		{StateProvisioned, StateRevoked},    // must be active first
		{StateActive, StateApproved},        // no going back
	}
	for _, tc := range invalid {
		if err := Transition(tc.from, tc.to); err == nil {
			t.Errorf("expected %s→%s invalid, got nil", tc.from, tc.to)
		}
	}
}

func TestTerminalStates(t *testing.T) {
	for _, s := range []RequestState{StateDenied, StateCancelled, StateRevoked, StateExpired} {
		if !IsTerminalState(s) {
			t.Errorf("expected %s terminal", s)
		}
	}
	for _, s := range []RequestState{StateRequested, StateApproved, StateProvisioning, StateProvisioned, StateActive, StateProvisionFailed} {
		if IsTerminalState(s) {
			t.Errorf("expected %s non-terminal", s)
		}
	}
}

func TestCreateRequestWritesInitialHistoryAndAudit(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	req, err := svc.CreateRequest(ctx, CreateAccessRequestInput{
		WorkspaceID: ws,
		RequesterID: "user-1",
		ResourceRef: "repo:acme/api",
		Role:        "write",
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if req.State != StateRequested {
		t.Fatalf("expected requested, got %s", req.State)
	}
	if req.TargetUserID != "user-1" {
		t.Fatalf("expected target defaulted to requester, got %s", req.TargetUserID)
	}

	hist, err := svc.History(ctx, ws, req.ID)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 || hist[0].FromState != "" || hist[0].ToState != StateRequested {
		t.Fatalf("expected initial ''→requested history, got %+v", hist)
	}

	var audits int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ?", ws).Count(&audits)
	if audits != 1 {
		t.Fatalf("expected 1 audit event, got %d", audits)
	}
}

func TestApproveDenyCancelTransitions(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	mk := func() uuid.UUID {
		r, err := svc.CreateRequest(ctx, CreateAccessRequestInput{WorkspaceID: ws, RequesterID: "u", ResourceRef: "r", Role: "read"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		return r.ID
	}

	id := mk()
	if err := svc.ApproveRequest(ctx, ws, id, "mgr", ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, _ := svc.GetRequest(ctx, ws, id)
	if got.State != StateApproved {
		t.Fatalf("expected approved, got %s", got.State)
	}
	// approving again is invalid (approved→approved not allowed)
	if err := svc.ApproveRequest(ctx, ws, id, "mgr", ""); err == nil {
		t.Fatal("expected error re-approving")
	}

	id2 := mk()
	if err := svc.DenyRequest(ctx, ws, id2, "mgr", "nope"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	got2, _ := svc.GetRequest(ctx, ws, id2)
	if got2.State != StateDenied {
		t.Fatalf("expected denied, got %s", got2.State)
	}
}

func TestTenantIsolationCrossWorkspaceInvisible(t *testing.T) {
	db := newTestDB(t)
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	svc := NewAccessRequestService(db)
	ctx := context.Background()

	req, err := svc.CreateRequest(ctx, CreateAccessRequestInput{WorkspaceID: wsA, RequesterID: "u", ResourceRef: "r", Role: "read"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Workspace B cannot see or transition workspace A's request.
	if _, err := svc.GetRequest(ctx, wsB, req.ID); err != ErrRequestNotFound {
		t.Fatalf("expected ErrRequestNotFound cross-tenant, got %v", err)
	}
	if err := svc.ApproveRequest(ctx, wsB, req.ID, "attacker", ""); err != ErrRequestNotFound {
		t.Fatalf("expected ErrRequestNotFound on cross-tenant approve, got %v", err)
	}
	// Still requested in A.
	got, _ := svc.GetRequest(ctx, wsA, req.ID)
	if got.State != StateRequested {
		t.Fatalf("cross-tenant approve leaked: state=%s", got.State)
	}
}

func TestWorkflowRouting(t *testing.T) {
	cases := []struct {
		risk    string
		factors []string
		want    string
	}{
		{RiskLow, nil, WorkflowStepAutoApprove},
		{RiskMedium, nil, WorkflowStepManagerApproval},
		{RiskHigh, nil, WorkflowStepSecurityReview},
		{"", nil, WorkflowStepManagerApproval},
		{RiskLow, []string{SensitiveResourceRiskFactor}, WorkflowStepSecurityReview},
		{RiskMedium, []string{"sensitive_resource"}, WorkflowStepSecurityReview},
	}
	for _, tc := range cases {
		got := Route(tc.risk, tc.factors)
		if got.StepType != tc.want {
			t.Errorf("Route(%q,%v)=%s want %s", tc.risk, tc.factors, got.StepType, tc.want)
		}
	}
}

func TestExecuteWorkflowAutoApprovesLowRisk(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	reqSvc := NewAccessRequestService(db)
	wf := NewWorkflowService(reqSvc)
	ctx := context.Background()

	req, _ := reqSvc.CreateRequest(ctx, CreateAccessRequestInput{
		WorkspaceID: ws, RequesterID: "u", ResourceRef: "r", Role: "read", RiskLevel: RiskLow,
	})
	dec, err := wf.ExecuteWorkflow(ctx, ws, req, "system")
	if err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if !dec.Approved {
		t.Fatalf("expected auto-approved")
	}
	got, _ := reqSvc.GetRequest(ctx, ws, req.ID)
	if got.State != StateApproved {
		t.Fatalf("expected approved, got %s", got.State)
	}
}

func TestExecuteWorkflowParksHighRisk(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	reqSvc := NewAccessRequestService(db)
	wf := NewWorkflowService(reqSvc)
	ctx := context.Background()

	req, _ := reqSvc.CreateRequest(ctx, CreateAccessRequestInput{
		WorkspaceID: ws, RequesterID: "u", ResourceRef: "r", Role: "admin", RiskLevel: RiskHigh,
	})
	dec, err := wf.ExecuteWorkflow(ctx, ws, req, "system")
	if err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	if dec.Approved || dec.StepType != WorkflowStepSecurityReview {
		t.Fatalf("expected parked for security review, got %+v", dec)
	}
	got, _ := reqSvc.GetRequest(ctx, ws, req.ID)
	if got.State != StateRequested {
		t.Fatalf("expected still requested, got %s", got.State)
	}
}

// fakeConnector is an in-test AccessConnector whose Provision/Revoke behavior
// is scripted by the test. It doubles as a ConnectorResolver returning itself.
type fakeConnector struct {
	provisionErr   error
	revokeErr      error
	resolveErr     error // when set, Resolve fails (e.g. simulating a rotated DEK)
	provisionCnt   int
	revokeCnt      int
	revokeSessCnt  int
	failNProvision int  // fail this many times before succeeding
	ssoEnforced    bool // returned by CheckSSOEnforcement
	ssoDetails     string
	identities     []*access.Identity

	entitlements     []access.Entitlement // returned by ListEntitlements
	revokeFailFor    map[string]bool      // ResourceExternalID -> force RevokeAccess error
	revokedResources []string             // ResourceExternalIDs RevokeAccess was called for
}

func (f *fakeConnector) Resolve(_ context.Context, _, _ uuid.UUID) (*ResolvedConnector, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return &ResolvedConnector{Provider: "fake", Impl: f}, nil
}

func (f *fakeConnector) Validate(context.Context, map[string]any, map[string]any) error {
	return nil
}
func (f *fakeConnector) Connect(context.Context, map[string]any, map[string]any) error {
	return nil
}
func (f *fakeConnector) VerifyPermissions(context.Context, map[string]any, map[string]any, []string) ([]string, error) {
	return nil, nil
}
func (f *fakeConnector) CountIdentities(context.Context, map[string]any, map[string]any) (int, error) {
	return len(f.identities), nil
}
func (f *fakeConnector) SyncIdentities(_ context.Context, _ map[string]any, _ map[string]any, _ string, handler func(batch []*access.Identity, nextCheckpoint string) error) error {
	batch := f.identities
	if batch == nil {
		batch = []*access.Identity{}
	}
	return handler(batch, "")
}
func (f *fakeConnector) ProvisionAccess(context.Context, map[string]any, map[string]any, access.AccessGrant) error {
	f.provisionCnt++
	if f.failNProvision > 0 {
		f.failNProvision--
		return errFakeProvision
	}
	return f.provisionErr
}
func (f *fakeConnector) RevokeAccess(_ context.Context, _, _ map[string]any, grant access.AccessGrant) error {
	f.revokeCnt++
	f.revokedResources = append(f.revokedResources, grant.ResourceExternalID)
	if f.revokeFailFor[grant.ResourceExternalID] {
		return errFakeRevoke
	}
	return f.revokeErr
}
func (f *fakeConnector) ListEntitlements(context.Context, map[string]any, map[string]any, string) ([]access.Entitlement, error) {
	return f.entitlements, nil
}
func (f *fakeConnector) GetSSOMetadata(context.Context, map[string]any, map[string]any) (*access.SSOMetadata, error) {
	return &access.SSOMetadata{Protocol: "oidc"}, nil
}
func (f *fakeConnector) GetCredentialsMetadata(context.Context, map[string]any, map[string]any) (map[string]any, error) {
	return map[string]any{}, nil
}

// RevokeUserSessions implements access.SessionRevoker (kill-switch layer).
func (f *fakeConnector) RevokeUserSessions(context.Context, map[string]any, map[string]any, string) error {
	f.revokeSessCnt++
	return nil
}

// CheckSSOEnforcement implements access.SSOEnforcementChecker.
func (f *fakeConnector) CheckSSOEnforcement(context.Context, map[string]any, map[string]any) (bool, string, error) {
	return f.ssoEnforced, f.ssoDetails, nil
}

var errFakeProvision = &fakeErr{"provision boom"}
var errFakeRevoke = &fakeErr{"revoke boom"}

type fakeErr struct{ s string }

func (e *fakeErr) Error() string { return e.s }
