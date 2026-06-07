package aiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAssessRiskWithFallback_AgentDown_FailSafe(t *testing.T) {
	c := NewAIClient("", nil, "") // unconfigured → always fails
	got := AssessRiskWithFallback(context.Background(), c, "", RiskAssessmentInput{Role: "admin"}, false)
	if got.Score != DefaultRiskScore {
		t.Errorf("Score = %q; want %q (fail-safe)", got.Score, DefaultRiskScore)
	}
	if !got.Degraded {
		t.Error("expected Degraded=true on fallback")
	}
	if len(got.Factors) == 0 || got.Factors[0] != aiUnavailableFactor {
		t.Errorf("Factors = %v; want %q", got.Factors, aiUnavailableFactor)
	}
}

func TestAssessRiskWithFallback_AgentDown_FailClosed(t *testing.T) {
	c := NewAIClient("", nil, "")
	got := AssessRiskWithFallback(context.Background(), c, "", RiskAssessmentInput{Role: "admin"}, true)
	if got.Score != FailClosedRiskScore {
		t.Errorf("Score = %q; want %q (fail-closed)", got.Score, FailClosedRiskScore)
	}
	if !got.Degraded {
		t.Error("expected Degraded=true on fallback")
	}
}

func TestAssessRiskWithFallback_HappyPath(t *testing.T) {
	ca := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{RiskScore: "LOW", RiskFactors: []string{"short_duration"}})
	})
	srv, clientTLS := mtlsServer(t, ca, handler)
	c := newClientFor(srv, clientTLS, "")

	got := AssessRiskWithFallback(context.Background(), c, "local_4b", RiskAssessmentInput{Role: "viewer"}, false)
	if got.Degraded {
		t.Error("did not expect Degraded on happy path")
	}
	if got.Score != RiskLow { // normalizeScore lowercases "LOW"
		t.Errorf("Score = %q; want low", got.Score)
	}
}

func TestAutomateReviewWithFallback_AgentDown_DefersToHuman(t *testing.T) {
	c := NewAIClient("", nil, "")
	got := AutomateReviewWithFallback(context.Background(), c, "", ReviewAutomationInput{Role: "admin"})
	if got.Decision != ReviewDecisionManual {
		t.Errorf("Decision = %q; want %q (never auto revoke/certify on outage)", got.Decision, ReviewDecisionManual)
	}
	if !got.Degraded {
		t.Error("expected Degraded=true")
	}
}

func TestAutomateReviewWithFallback_EmptyDecisionCoercedToManual(t *testing.T) {
	ca := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{}) // no decision field
	})
	srv, clientTLS := mtlsServer(t, ca, handler)
	c := newClientFor(srv, clientTLS, "")
	got := AutomateReviewWithFallback(context.Background(), c, "", ReviewAutomationInput{Role: "admin"})
	if got.Decision != ReviewDecisionManual {
		t.Errorf("Decision = %q; want %q", got.Decision, ReviewDecisionManual)
	}
}

func TestDetectAnomaliesWithFallback_AgentDown_EmptySlice(t *testing.T) {
	c := NewAIClient("", nil, "")
	got := DetectAnomaliesWithFallback(context.Background(), c, "", AnomalyDetectionInput{GrantID: "g1"})
	if len(got) != 0 {
		t.Errorf("anomalies = %v; want empty on outage (advisory only)", got)
	}
}

func TestAssessSessionRiskWithFallback_FailClosed(t *testing.T) {
	c := NewAIClient("", nil, "")
	got := AssessSessionRiskWithFallback(context.Background(), c, "", SessionRiskInput{UserExternalID: "u1"}, true)
	if got.Score != FailClosedRiskScore {
		t.Errorf("Score = %q; want %q", got.Score, FailClosedRiskScore)
	}
	if !got.Degraded {
		t.Error("expected Degraded=true")
	}
}

func TestRecommendPolicyWithFallback_AgentDown_Empty(t *testing.T) {
	c := NewAIClient("", nil, "")
	if got := RecommendPolicyWithFallback(context.Background(), c, "", PolicyRecommendationInput{WorkspaceID: "ws1"}); got != "" {
		t.Errorf("explanation = %q; want empty on outage", got)
	}
}

func TestAnalyzeBehaviourWithFallback_AgentDown_EmptySlice(t *testing.T) {
	c := NewAIClient("", nil, "")
	got := AnalyzeBehaviourWithFallback(context.Background(), c, "", BehaviourAnalyticsInput{UserExternalID: "u1"})
	if len(got) != 0 {
		t.Errorf("anomalies = %v; want empty on outage (advisory only)", got)
	}
}

func TestAnalyzeBehaviourWithFallback_HappyPath(t *testing.T) {
	ca := newTestCA(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(SkillResponse{Anomalies: []AnomalyEvent{{Kind: "off_hours_sessions", Severity: "medium", Confidence: 0.6}}})
	})
	srv, clientTLS := mtlsServer(t, ca, handler)
	c := newClientFor(srv, clientTLS, "")

	got := AnalyzeBehaviourWithFallback(context.Background(), c, "", BehaviourAnalyticsInput{
		UserExternalID: "u1",
		Sessions:       []BehaviourSession{{StartHour: 3, CommandCount: 5}},
		Baseline:       &BehaviourBaseline{Targets: []string{"db-stage"}, AvgCommandCount: 10},
	})
	if len(got) != 1 || got[0].Kind != "off_hours_sessions" {
		t.Errorf("anomalies = %+v; want one off_hours_sessions event", got)
	}
}

func TestNormalizeScore(t *testing.T) {
	// Slice (not a map) so the deliberately whitespace-padded input " High "
	// — which exercises trimming — is not flagged as a suspicious map key.
	cases := []struct {
		in   string
		want string
	}{
		{"low", RiskLow},
		{"MEDIUM", RiskMedium},
		{" High ", RiskHigh},
		{"", DefaultRiskScore},
		{"bogus", DefaultRiskScore},
	}
	for _, tc := range cases {
		if got := normalizeScore(tc.in); got != tc.want {
			t.Errorf("normalizeScore(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
