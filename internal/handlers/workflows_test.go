package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// TestEmergencyOffboardRecordsReasonInAudit is the regression test for the
// break-glass compliance gap: the emergency-offboard endpoint accepted a
// `reason` in its body but never persisted it. A break-glass kill switch gated
// by step-up MFA must record the operator's justification in the per-workspace
// audit hash chain, so the reason is asserted to land on a dedicated
// workflow.emergency_offboard.initiated event.
func TestEmergencyOffboardRecordsReasonInAudit(t *testing.T) {
	deps := lifecycleTestDeps(t)
	r := NewRouter(deps)

	const reason = "terminated for cause — revoke all access immediately"
	w := do(t, r, http.MethodPost, "/api/v1/emergency-offboard", "tok-a-mfa", map[string]any{
		"user_external_id": "ext-leaver",
		"reason":           reason,
	})
	// No grants exist for the user, so every layer is a no-op success → 200.
	if w.Code != http.StatusOK {
		t.Fatalf("emergency-offboard status = %d, body=%s", w.Code, w.Body.String())
	}

	var ev models.AuditEvent
	err := deps.DB.
		Where("action = ? AND target_ref = ?", "workflow.emergency_offboard.initiated", "ext-leaver").
		Take(&ev).Error
	if err != nil {
		t.Fatalf("expected an emergency_offboard.initiated audit event: %v", err)
	}
	if ev.Actor != "user-a" {
		t.Fatalf("audit actor = %q, want the authenticated admin %q (never the request body)", ev.Actor, "user-a")
	}
	if !strings.Contains(string(ev.Metadata), reason) {
		t.Fatalf("audit metadata %q does not carry the operator reason %q", string(ev.Metadata), reason)
	}
}

// TestEmergencyOffboardRequiresMFA confirms the break-glass route stays behind
// the step-up MFA gate (a non-MFA token is rejected before any layer runs).
func TestEmergencyOffboardRequiresMFA(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodPost, "/api/v1/emergency-offboard", "tok-a", map[string]any{
		"user_external_id": "ext-leaver",
		"reason":           "x",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("emergency-offboard without MFA status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}
