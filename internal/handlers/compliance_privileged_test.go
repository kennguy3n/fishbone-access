package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestPrivilegedAccessEndpoint exercises the new privileged-access coverage
// read surface end-to-end: it is RBAC-gated like the rest of the read surface,
// it returns a well-formed coverage document, and it validates the period
// query params. The non-zero counting itself is covered by the service-level
// tests in internal/services/compliance.
func TestPrivilegedAccessEndpoint(t *testing.T) {
	r := NewRouter(complianceTestDeps(t))
	const route = "/api/v1/compliance/privileged-access"

	// Operator is excluded from compliance entirely -> 403.
	if w := do(t, r, http.MethodGet, route, "tok-a", nil); w.Code != http.StatusForbidden {
		t.Fatalf("operator GET %s: got %d body=%s, want 403", route, w.Code, w.Body.String())
	}

	// Auditor holds compliance.read -> 200 with a parseable coverage document.
	w := do(t, r, http.MethodGet, route, "tok-auditor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("auditor GET %s: got %d body=%s, want 200", route, w.Code, w.Body.String())
	}
	var cov struct {
		Monitored     bool `json:"monitored"`
		Sessions      int  `json:"sessions"`
		Commands      int  `json:"commands"`
		Recordings    int  `json:"recordings"`
		EvidenceTotal int  `json:"evidence_total"`
		Controls      []struct {
			ID        string `json:"id"`
			Framework string `json:"framework"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cov); err != nil {
		t.Fatalf("unmarshal coverage: %v (body=%s)", err, w.Body.String())
	}
	// With no PAM activity seeded, the panel is honest: not monitored, zero.
	if cov.Monitored || cov.EvidenceTotal != 0 {
		t.Fatalf("expected unmonitored empty coverage, got %+v", cov)
	}
	// The privileged-access control family must still be enumerated so the UI
	// can render the (currently zero) CC6.7 / A.8.2 rows.
	if len(cov.Controls) == 0 {
		t.Fatalf("expected privileged-access controls enumerated even when empty")
	}

	// A malformed period bound fails closed with 400.
	if w := do(t, r, http.MethodGet, route+"?from=not-a-time", "tok-auditor", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad from param: got %d body=%s, want 400", w.Code, w.Body.String())
	}
}
