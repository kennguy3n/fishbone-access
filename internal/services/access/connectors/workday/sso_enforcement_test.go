package workday

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/authentication/v1/policies") {
			t.Errorf("path=%q; want suffix /api/authentication/v1/policies", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"data":[{"name":"default","active":true,"requireFederatedAuthentication":true,"allowsPasswordFallback":false}]}`))
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

func TestCheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"name":"default","active":true,"requireFederatedAuthentication":true,"allowsPasswordFallback":true}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced=true; want false")
	}
}

// TestCheckSSOEnforcement_NoActivePolicy guards against falsely reporting SSO
// as enforced when no authentication policy is active. With every policy
// inactive, the loop skips all of them; without an explicit "no active policy"
// guard, execution falls through to the optimistic `return true`, masking a
// security gap. Zero active policies means at least one non-SSO login path is
// reachable, so enforced must be false.
func TestCheckSSOEnforcement_NoActivePolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"name":"legacy","active":false,"requireFederatedAuthentication":true,"allowsPasswordFallback":false}]}`))
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
		t.Errorf("enforced=true with no active policy; want false (details=%q)", details)
	}
}

func TestCheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if _, _, err := c.CheckSSOEnforcement(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}
