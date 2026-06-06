package jira

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func jiraSSOConfig() map[string]interface{} {
	return map[string]interface{}{"cloud_id": "cid-1", "site_url": "https://acme.atlassian.net", "org_id": "org-1"}
}
func jiraSSOSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "tok", "email": "admin@acme.com"}
}

func TestJira_CheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/admin/v1/orgs/org-1/authentication-policies") {
			t.Errorf("path=%q; want suffix /admin/v1/orgs/org-1/authentication-policies", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"p1","attributes":{"name":"Default","ssoOnly":true}}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), jiraSSOConfig(), jiraSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Fatalf("enforced=false; want true (details=%q)", details)
	}
}

func TestJira_CheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"p1","attributes":{"name":"Default","ssoOnly":false}}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), jiraSSOConfig(), jiraSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Fatal("enforced=true; want false")
	}
}

func TestJira_CheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if _, _, err := c.CheckSSOEnforcement(context.Background(), jiraSSOConfig(), jiraSSOSecrets()); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestJira_SatisfiesSSOEnforcementCheckerInterface(t *testing.T) {
	var _ interface {
		CheckSSOEnforcement(context.Context, map[string]interface{}, map[string]interface{}) (bool, string, error)
	} = New()
}
