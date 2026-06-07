package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestSplunk_CheckSSOEnforcement_SAMLEnvelope(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/services/properties/authentication/authentication/authType") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "authType", "content": "SAML"},
			},
		})
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced = false; want true (SAML)")
	}
	if !strings.Contains(details, "authType=SAML") {
		t.Errorf("details = %q", details)
	}
}

func TestSplunk_CheckSSOEnforcement_SplunkLocal(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "authType", "content": "Splunk"},
			},
		})
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced = true; want false (Splunk local auth)")
	}
	if !strings.Contains(details, "authType=Splunk") {
		t.Errorf("details = %q", details)
	}
}

func TestSplunk_CheckSSOEnforcement_LDAP(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "authType", "content": "LDAP"},
			},
		})
	})
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced = true; want false (LDAP is not SAML)")
	}
}

func TestSplunk_CheckSSOEnforcement_RawString(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("SAML"))
	})
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced = false; want true (raw SAML body)")
	}
}

// TestSplunk_CheckSSOEnforcement_EmptyEnvelope verifies that a
// well-formed JSON envelope with an empty `entry` array is reported
// as an empty authType (assume local Splunk auth) instead of leaking
// the raw JSON body into the detail string. Regression test for the
// Devin Review finding on PR #181.
func TestSplunk_CheckSSOEnforcement_EmptyEnvelope(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{},
		})
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced = true; want false (empty envelope ≠ SAML)")
	}
	if strings.Contains(details, "{") || strings.Contains(details, "entry") {
		t.Errorf("details leaked raw JSON: %q", details)
	}
	if !strings.Contains(details, "authType field empty") {
		t.Errorf("details = %q; want empty-authType message", details)
	}
}

// TestSplunk_CheckSSOEnforcement_EnvelopeEmptyContent verifies that a
// well-formed envelope whose entry[0].content is empty is treated as
// an empty authType (not as the raw envelope body).
func TestSplunk_CheckSSOEnforcement_EnvelopeEmptyContent(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entry": []map[string]interface{}{
				{"name": "authType", "content": ""},
			},
		})
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced = true; want false (empty content ≠ SAML)")
	}
	if strings.Contains(details, "{") || strings.Contains(details, "entry") {
		t.Errorf("details leaked raw JSON: %q", details)
	}
}

// TestSplunk_CheckSSOEnforcement_HTMLErrorBody verifies the fix for
// the residual ugly-detail-string bug: when an upstream reverse proxy
// or load balancer in front of Splunk returns an HTML error page
// (200 OK with an HTML body — Splunk's `/services/properties/...`
// endpoint never returns HTML on its own, so this is by definition
// an interposing layer), CheckSSOEnforcement MUST NOT classify the
// response as a confirmed "not_enforced" (which would fire a
// false-positive SSO-regression alert on the daily orphan-reconciler
// scan). Per the SSOEnforcementChecker contract — see
// optional_interfaces.go — non-nil error maps to "unknown" enforcement
// state, which is the correct surface for a check that could not
// complete. The error message MUST NOT echo the body verbatim
// (megabytes-long, may contain sensitive trace IDs / cookies /
// stack frames that the interposing layer chose to render); only a
// kind+length hint is exposed so operators can route the incident.
func TestSplunk_CheckSSOEnforcement_HTMLErrorBody(t *testing.T) {
	htmlBody := `<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1><p>The proxy server received an invalid response from an upstream server.</p><pre>x-amzn-trace-id=Root=1-abc-1234567890abcdef secret-cookie=do-not-echo</pre></body></html>`
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(htmlBody))
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("CheckSSOEnforcement: err = nil; want non-nil (contract requires 'unknown' state for unparseable upstream response, not silent 'not_enforced')")
	}
	if enforced {
		t.Errorf("enforced = true; want false on error")
	}
	if details != "" {
		t.Errorf("details = %q; want empty string when err != nil (contract: caller surfaces error.Error())", details)
	}
	msg := err.Error()
	if strings.Contains(msg, "<html") ||
		strings.Contains(msg, "502 Bad Gateway") ||
		strings.Contains(msg, "secret-cookie") ||
		strings.Contains(msg, "x-amzn-trace-id") {
		t.Errorf("error leaked HTML body content: %q", msg)
	}
	if !strings.Contains(msg, "unparseable") {
		t.Errorf("error should mention 'unparseable'; got %q", msg)
	}
	if !strings.Contains(msg, "kind=html") {
		t.Errorf("error should include 'kind=html' hint; got %q", msg)
	}
	if !strings.Contains(msg, "len=") {
		t.Errorf("error should include length hint; got %q", msg)
	}
}

// TestSplunk_CheckSSOEnforcement_PlaintextErrorBody verifies the same
// scrubbing happens for plaintext upstream errors (e.g., a maintenance
// page from nginx with `Content-Type: text/plain`). Plaintext with
// whitespace or non-ASCII characters fails the authType shape regex
// and so flows through the unparseable-response error path.
func TestSplunk_CheckSSOEnforcement_PlaintextErrorBody(t *testing.T) {
	plaintext := "We are down for maintenance — back in 30 minutes."
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(plaintext))
	})
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("CheckSSOEnforcement: err = nil; want non-nil (plaintext unparseable response must map to 'unknown', not silent 'not_enforced')")
	}
	if enforced {
		t.Errorf("enforced = true; want false on error")
	}
	if details != "" {
		t.Errorf("details = %q; want empty string when err != nil", details)
	}
	msg := err.Error()
	if strings.Contains(msg, "maintenance") || strings.Contains(msg, plaintext) {
		t.Errorf("error leaked plaintext body: %q", msg)
	}
	if !strings.Contains(msg, "kind=text") {
		t.Errorf("error should include 'kind=text' hint; got %q", msg)
	}
}

// TestSplunk_CheckSSOEnforcement_LargePlaintextBody verifies that a
// megabyte-scale upstream payload (e.g. a verbose stacktrace dumped
// by a misconfigured proxy) is reported as a sanitized error
// message rather than echoed into the surface. The 1MB body cap from
// connector.do() means a real-world body could plausibly reach this
// size before truncation. The bodyKind helper is bounded to inspect
// only the first 64 bytes — without that bound this test would
// allocate ~3MB just to identify a 14-byte HTML prefix.
func TestSplunk_CheckSSOEnforcement_LargePlaintextBody(t *testing.T) {
	huge := strings.Repeat("stack-frame-line-that-should-never-surface\n", 4096) // ~180 KB
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(huge))
	})
	_, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("CheckSSOEnforcement: err = nil; want non-nil")
	}
	msg := err.Error()
	if strings.Contains(msg, "stack-frame-line-that-should-never-surface") {
		t.Errorf("error leaked huge body content; first 200 chars: %q", msg[:min(len(msg), 200)])
	}
	if len(msg) > 256 {
		t.Errorf("error surface is unbounded (len=%d); want short sanitized message", len(msg))
	}
}

// TestSplunk_CheckSSOEnforcement_KnownAuthTypeRawString verifies the
// shape-admitted raw-string path still works for the known canonical
// values returned by older Splunk installations that don't honour
// `output_mode=json`. This is the positive case the scrubbing must
// continue to allow.
func TestSplunk_CheckSSOEnforcement_KnownAuthTypeRawString(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"SAML", "SAML", true},
		{"Splunk", "Splunk", false},
		{"LDAP", "LDAP", false},
		{"Scripted", "Scripted", false},
		{"future-OIDC", "OIDC", false},
		{"future-ProxySSO", "ProxySSO", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
			if err != nil {
				t.Fatalf("CheckSSOEnforcement: %v", err)
			}
			if enforced != tc.want {
				t.Errorf("enforced = %v; want %v", enforced, tc.want)
			}
			if !strings.Contains(details, "authType="+tc.body) {
				t.Errorf("details = %q; want authType=%s", details, tc.body)
			}
		})
	}
}

func TestSplunk_CheckSSOEnforcement_ServerErrorReturnsError(t *testing.T) {
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"messages":[{"type":"ERROR","text":"boom"}]}`))
	})
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Errorf("err = nil; want server error (must NOT silently return enforced=false)")
	}
	if enforced {
		t.Errorf("enforced should be false on error")
	}
}

func TestSplunk_CheckSSOEnforcement_ServerErrorJSONSurfacedVerbatim(t *testing.T) {
	// When Splunk itself returns a non-2xx response with a
	// JSON body (its native error format), the error message
	// must surface the body verbatim so operators can see the
	// upstream `messages[].text` content — that's actionable
	// triage detail (auth failures, capability denials,
	// configuration errors). The body-kind-aware scrubbing in
	// do() only kicks in for HTML / XML / plaintext bodies
	// (interposing reverse proxies / load balancers), not
	// JSON.
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"messages":[{"type":"ERROR","text":"capability denied: missing edit_user"}]}`))
	})
	_, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("err = nil; want server error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "capability denied: missing edit_user") {
		t.Errorf("error should surface Splunk-native JSON body verbatim; got %q", msg)
	}
	if strings.Contains(msg, "kind=") {
		t.Errorf("error should NOT contain kind= hint for JSON body (those are reserved for HTML/XML/text scrubbing); got %q", msg)
	}
}

func TestSplunk_CheckSSOEnforcement_ServerErrorHTMLProxyBodyScrubbed(t *testing.T) {
	// When a reverse proxy in front of Splunk returns a non-2xx
	// response with an HTML body (e.g. a 502 Bad Gateway error
	// page from a cloud load balancer), the error message must
	// scrub the body to a kind+length hint instead of echoing
	// the proxy's HTML. Those bodies frequently embed trace
	// IDs, cookie names, internal hostnames, and stack frames
	// that don't belong in operator dashboards or audit logs.
	htmlBody := `<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>` +
		`<body><h1>502 Bad Gateway</h1>` +
		`<p>x-amzn-trace-id: Root=1-secret-trace-id-do-not-log</p>` +
		`<p>set-cookie: AWSALB=secret-cookie-do-not-log</p>` +
		`</body></html>`
	_, c := newSplunkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(htmlBody))
	})
	_, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err == nil {
		t.Fatal("err = nil; want server error")
	}
	msg := err.Error()
	if strings.Contains(msg, "x-amzn-trace-id") ||
		strings.Contains(msg, "secret-trace-id") ||
		strings.Contains(msg, "AWSALB") ||
		strings.Contains(msg, "secret-cookie") {
		t.Errorf("error leaked HTML body content: %q", msg)
	}
	if !strings.Contains(msg, "kind=html") {
		t.Errorf("error should include 'kind=html' hint; got %q", msg)
	}
	if !strings.Contains(msg, "len=") {
		t.Errorf("error should include length hint; got %q", msg)
	}
}

// NOTE: payload kind-detection (HTML fragments, XML, JSON, whitespace)
// is now tested with the shared classifier in
// internal/services/access/httputil (see TestBodyKind). The SSO check
// reaches it via httputil.BodyKind; the unparseable-upstream → "unknown"
// behaviour is still exercised by the cases above.

func TestSplunk_SatisfiesSSOEnforcementCheckerInterface(t *testing.T) {
	var _ access.SSOEnforcementChecker = New()
}
