package pam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
)

// fakeAgent stands up an httptest TLS server that answers every /a2a/invoke and
// returns an AIClient wired to it (Configured()==true). Responses are looked up
// per skill_name (so the post-close path's risk and behavioural calls can return
// different payloads), and the last request envelope for each skill is recorded
// so a test can assert what the session manager sent.
type fakeAgent struct {
	srv    *httptest.Server
	byName map[string]aiclient.SkillResponse
	bodies map[string]map[string]any
}

func newFakeAgent(t *testing.T, byName map[string]aiclient.SkillResponse) (*aiclient.AIClient, *fakeAgent) {
	t.Helper()
	fa := &fakeAgent{byName: byName, bodies: map[string]map[string]any{}}
	fa.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		skill, _ := body["skill_name"].(string)
		fa.bodies[skill] = body
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fa.byName[skill])
	}))
	t.Cleanup(fa.srv.Close)
	c := aiclient.NewAIClient(fa.srv.URL, nil, "")
	c.SetHTTPClient(fa.srv.Client())
	return c, fa
}

// payloadFor returns the decoded "payload" object the manager sent for skill.
func (fa *fakeAgent) payloadFor(t *testing.T, skill string) map[string]any {
	t.Helper()
	body, ok := fa.bodies[skill]
	if !ok {
		t.Fatalf("no request recorded for skill %q", skill)
	}
	payload, ok := body["payload"].(map[string]any)
	if !ok {
		t.Fatalf("skill %q payload missing/!map: %#v", skill, body)
	}
	return payload
}

// leaseActiveSession mints+redeems a connect token so the test has a real active
// session (with the broker/vault wiring the production close path expects).
func leaseActiveSession(t *testing.T, db *gorm.DB, ws uuid.UUID, subject string) *LeasedSession {
	t.Helper()
	v := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, v, nil)
	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	raw, _, err := broker.MintConnectToken(context.Background(), MintInput{WorkspaceID: ws, TargetID: target.ID, Subject: subject, Actor: "admin"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	leased, err := broker.RedeemConnectToken(context.Background(), raw, "1.2.3.4")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	return leased
}

func countAudits(t *testing.T, db *gorm.DB, ws uuid.UUID, action string) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, action).
		Count(&n).Error; err != nil {
		t.Fatalf("count %s audits: %v", action, err)
	}
	return n
}

// A configured scorer turns a clean session close into exactly one
// pam.session.risk_assessed audit event carrying the agent's score.
func TestSessionManagerScoresSessionRiskOnClose(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	leased := leaseActiveSession(t, db, ws, "alice")

	ai, fa := newFakeAgent(t, map[string]aiclient.SkillResponse{
		aiclient.SkillPAMSessionRisk: {
			RiskScore:      "HIGH",
			RiskFactors:    []string{"off_hours", "destructive_command"},
			Recommendation: "review session transcript",
		},
	})
	mgr := NewSessionManager(db, nil, nil)
	mgr.SetRiskScorer(ai)

	// A couple of commands so the scorer has a transcript to send.
	for _, cmd := range []string{"whoami", "rm -rf /tmp/x"} {
		if _, err := mgr.LogCommand(context.Background(), leased.Session, cmd); err != nil {
			t.Fatalf("LogCommand: %v", err)
		}
	}

	if err := mgr.CloseSession(context.Background(), ws, leased.Session.ID); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	mgr.Drain() // post-close scoring is detached; wait for it before asserting.

	if got := countAudits(t, db, ws, "pam.session.risk_assessed"); got != 1 {
		t.Fatalf("want exactly 1 pam.session.risk_assessed audit, got %d", got)
	}

	var ev models.AuditEvent
	if err := db.Where("workspace_id = ? AND action = ?", ws, "pam.session.risk_assessed").Take(&ev).Error; err != nil {
		t.Fatalf("load risk audit: %v", err)
	}
	var md struct {
		RiskScore string `json:"risk_score"`
	}
	if err := json.Unmarshal(ev.Metadata, &md); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if md.RiskScore != aiclient.RiskHigh {
		t.Fatalf("risk_score = %q; want %q", md.RiskScore, aiclient.RiskHigh)
	}

	// The scorer forwarded the session's command transcript and source IP.
	payload := fa.payloadFor(t, aiclient.SkillPAMSessionRisk)
	if payload["source_ip"] != "1.2.3.4" {
		t.Fatalf("source_ip = %v; want 1.2.3.4", payload["source_ip"])
	}
	if got := payload["commands"].([]any); len(got) != 2 {
		t.Fatalf("want 2 commands forwarded, got %v", payload["commands"])
	}
}

// A configured scorer also runs behavioural analytics over the user's recent
// sessions on close and records each returned anomaly as a
// pam.session.behaviour_anomaly audit event.
func TestSessionManagerRecordsBehaviourAnomaliesOnClose(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	leased := leaseActiveSession(t, db, ws, "alice")

	ai, fa := newFakeAgent(t, map[string]aiclient.SkillResponse{
		aiclient.SkillPAMBehavioural: {
			Anomalies: []aiclient.AnomalyEvent{
				{Kind: "new_target", Severity: "high", Reason: "first access to target", Confidence: 0.9},
			},
		},
	})
	mgr := NewSessionManager(db, nil, nil)
	mgr.SetRiskScorer(ai)

	if err := mgr.CloseSession(context.Background(), ws, leased.Session.ID); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	mgr.Drain() // post-close scoring is detached; wait for it before asserting.

	if got := countAudits(t, db, ws, "pam.session.behaviour_anomaly"); got != 1 {
		t.Fatalf("want 1 pam.session.behaviour_anomaly audit, got %d", got)
	}
	// The behavioural call carried the closed session and a baseline.
	payload := fa.payloadFor(t, aiclient.SkillPAMBehavioural)
	if payload["user_external_id"] != "alice" {
		t.Fatalf("user_external_id = %v; want alice", payload["user_external_id"])
	}
	if _, ok := payload["baseline"].(map[string]any); !ok {
		t.Fatalf("behavioural payload missing baseline: %#v", payload)
	}
	if got, ok := payload["sessions"].([]any); !ok || len(got) == 0 {
		t.Fatalf("behavioural payload missing sessions: %#v", payload)
	}
}

// AnalyzeUserBehaviour with no recent sessions for the user is a clean no-op:
// no agent call result is persisted.
func TestAnalyzeUserBehaviourNoSessionsNoop(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")

	ai, _ := newFakeAgent(t, map[string]aiclient.SkillResponse{
		aiclient.SkillPAMBehavioural: {
			Anomalies: []aiclient.AnomalyEvent{{Kind: "should_not_be_used"}},
		},
	})
	mgr := NewSessionManager(db, nil, nil)
	mgr.SetRiskScorer(ai)

	anomalies, err := mgr.AnalyzeUserBehaviour(context.Background(), ws, "ghost")
	if err != nil {
		t.Fatalf("AnalyzeUserBehaviour: %v", err)
	}
	if len(anomalies) != 0 {
		t.Fatalf("want no anomalies for a user with no sessions, got %d", len(anomalies))
	}
	if got := countAudits(t, db, ws, "pam.session.behaviour_anomaly"); got != 0 {
		t.Fatalf("want 0 behaviour anomaly audits, got %d", got)
	}
}

// With no scorer configured the close path is unchanged: a normal closed audit,
// and no risk-assessed event (the agent-less default pays nothing).
func TestSessionManagerNoRiskScoringWhenUnconfigured(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	leased := leaseActiveSession(t, db, ws, "alice")

	mgr := NewSessionManager(db, nil, nil) // no SetRiskScorer
	if err := mgr.CloseSession(context.Background(), ws, leased.Session.ID); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	mgr.Drain()

	if got := countAudits(t, db, ws, "pam.session.closed"); got != 1 {
		t.Fatalf("want 1 pam.session.closed audit, got %d", got)
	}
	if got := countAudits(t, db, ws, "pam.session.risk_assessed"); got != 0 {
		t.Fatalf("want 0 pam.session.risk_assessed audits, got %d", got)
	}
}

// A degraded (agent-unreachable) result is advisory and must NOT be persisted as
// a synthetic signal: scoring against an unreachable agent produces no audit.
func TestSessionManagerDegradedScoringNotPersisted(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	leased := leaseActiveSession(t, db, ws, "alice")

	// Configured() but pointing at a server that always 500s → InvokeSkill
	// errors → AssessSessionRiskWithFallback returns Degraded=true.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	ai := aiclient.NewAIClient(srv.URL, nil, "")
	ai.SetHTTPClient(srv.Client())

	mgr := NewSessionManager(db, nil, nil)
	mgr.SetRiskScorer(ai)
	if err := mgr.CloseSession(context.Background(), ws, leased.Session.ID); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	mgr.Drain() // wait for the detached scoring to finish (and fail) before asserting.
	if got := countAudits(t, db, ws, "pam.session.risk_assessed"); got != 0 {
		t.Fatalf("degraded scoring must not persist; got %d risk audits", got)
	}
}
