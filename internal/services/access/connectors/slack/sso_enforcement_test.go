package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/team.info") {
			t.Errorf("path=%q; want suffix /team.info", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"team":{"sso_provider":{"type":"saml"}},"enterprise":{"is_sso_enabled":true}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Error("enforced=false; want true")
	}
}

// A SAML provider that is merely *configured* while password sign-in is
// still allowed (is_sso_enabled=false) must NOT report enforced=true.
// Enforcement requires both signals; reporting true here would be a
// false positive that hides a real security gap.
func TestCheckSSOEnforcement_ProviderWiredButPasswordAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"team":{"sso_provider":{"type":"saml"}},"enterprise":{"is_sso_enabled":false}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	enforced, reason, err := c.CheckSSOEnforcement(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Errorf("enforced=true; want false (provider wired but password allowed): %s", reason)
	}
}

func TestCheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"team":{"sso_provider":{"type":"none"}}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Error("enforced=true; want false")
	}
}

func TestCheckSSOEnforcement_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"missing_scope"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if _, _, err := c.CheckSSOEnforcement(context.Background(), nil, validSecrets()); err == nil {
		t.Fatal("err=nil; want non-nil on api error")
	}
}
