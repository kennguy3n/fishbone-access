package ping_identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// signOnPoliciesPayload returns a HAL response with a single default
// policy whose ID is "policy-1".
func signOnPoliciesPayload(t *testing.T, hasDefault bool) []byte {
	t.Helper()
	policies := []map[string]interface{}{
		{
			"id":         "policy-1",
			"name":       "default-saml",
			"default":    hasDefault,
			"policyType": "AUTHENTICATION",
		},
	}
	payload := map[string]interface{}{
		"_embedded": map[string]interface{}{
			"signOnPolicies": policies,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// actionsPayload returns a HAL response containing the given action types.
func actionsPayload(t *testing.T, types ...string) []byte {
	t.Helper()
	actions := make([]map[string]interface{}, 0, len(types))
	for i, ty := range types {
		actions = append(actions, map[string]interface{}{
			"id":       fmt.Sprintf("action-%d", i),
			"type":     ty,
			"priority": i + 1,
		})
	}
	payload := map[string]interface{}{
		"_embedded": map[string]interface{}{
			"actions": actions,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies/policy-1/actions"):
			_, _ = w.Write(actionsPayload(t, "IDENTITY_PROVIDER", "MULTI_FACTOR_AUTHENTICATION"))
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies"):
			_, _ = w.Write(signOnPoliciesPayload(t, true))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Errorf("enforced=false; want true (details=%q)", details)
	}
}

// TestCheckSSOEnforcement_LoginActionMeansNotEnforced is the regression
// test for: a default policy that still
// includes a LOGIN action (username + password fallback) MUST NOT be
// reported as SSO-enforced even though it is marked default.
func TestCheckSSOEnforcement_LoginActionMeansNotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies/policy-1/actions"):
			_, _ = w.Write(actionsPayload(t, "LOGIN", "MULTI_FACTOR_AUTHENTICATION"))
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies"):
			_, _ = w.Write(signOnPoliciesPayload(t, true))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false (details=%q)", details)
	}
	if !strings.Contains(details, "LOGIN") {
		t.Errorf("details=%q; want mention of LOGIN action", details)
	}
}

// TestCheckSSOEnforcement_NoIDPActionMeansNotEnforced covers a policy
// whose actions are MFA-only with neither LOGIN nor IDENTITY_PROVIDER —
// the first-factor sign-in path is unspecified so we report not enforced.
func TestCheckSSOEnforcement_NoIDPActionMeansNotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies/policy-1/actions"):
			_, _ = w.Write(actionsPayload(t, "MULTI_FACTOR_AUTHENTICATION"))
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies"):
			_, _ = w.Write(signOnPoliciesPayload(t, true))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false (details=%q)", details)
	}
	if !strings.Contains(details, "IDENTITY_PROVIDER") {
		t.Errorf("details=%q; want mention of IDENTITY_PROVIDER", details)
	}
}

func TestCheckSSOEnforcement_NoPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies"):
			_, _ = w.Write([]byte(`{"_embedded":{"signOnPolicies":[]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false (details=%q)", details)
	}
}

func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

// TestCheckSSOEnforcement_ActionsFetchFailure verifies that a 5xx on
// the actions endpoint surfaces an error so callers map the connector
// to "unknown" rather than silently returning enforced=false.
func TestCheckSSOEnforcement_ActionsFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/as/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies/policy-1/actions"):
			w.WriteHeader(http.StatusInternalServerError)
		case strings.HasSuffix(r.URL.Path, "/signOnPolicies"):
			_, _ = w.Write(signOnPoliciesPayload(t, true))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on 500 from actions endpoint")
	}
}
