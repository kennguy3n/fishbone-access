package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newOktaConfigSecrets(serverURL string) (map[string]interface{}, map[string]interface{}) {
	return map[string]interface{}{
			"okta_domain": "dev.okta.com",
		}, map[string]interface{}{
			"api_token": "SSWS-secret",
		}
}

// TestCheckSSOEnforcement_Enforced seeds an Okta sign-on policy
// with one ACTIVE rule that requires FEDERATED. The connector
// should report enforced=true.
func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/policies" && r.URL.Query().Get("type") == "OKTA_SIGN_ON":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"p1","status":"ACTIVE"}]`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/policies/p1/rules"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"status":"ACTIVE","actions":{"signon":{"requireFactor":{"factor":"FEDERATED"}}}}]`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c := New()
	c.urlOverride = server.URL
	cfg, sec := newOktaConfigSecrets(server.URL)
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced = false; want true (FEDERATED rule active)")
	}
	if details == "" {
		t.Error("details is empty; want a non-empty hint")
	}
}

// TestCheckSSOEnforcement_NotEnforced seeds a sign-on policy whose
// only ACTIVE rule does not require federation. The connector
// should report enforced=false with a hint about password sign-on.
func TestCheckSSOEnforcement_NotEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/policies":
			_, _ = w.Write([]byte(`[{"id":"p1","status":"ACTIVE"}]`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/policies/p1/rules"):
			_, _ = w.Write([]byte(`[{"status":"ACTIVE","actions":{"signon":{"requireFactor":{"factor":"PASSWORD"}}}}]`))
		}
	}))
	defer server.Close()
	c := New()
	c.urlOverride = server.URL
	cfg, sec := newOktaConfigSecrets(server.URL)
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced = true; want false (PASSWORD rule)")
	}
	if !strings.Contains(details, "Password") {
		t.Errorf("details=%q; want mention of password sign-on", details)
	}
}

// TestCheckSSOEnforcement_HTTPFailure asserts a 5xx upstream error
// surfaces as a non-nil err so callers map it to "unknown" rather
// than "not enforced".
func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer server.Close()
	c := New()
	c.urlOverride = server.URL
	cfg, sec := newOktaConfigSecrets(server.URL)
	_, _, err := c.CheckSSOEnforcement(context.Background(), cfg, sec)
	if err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}
