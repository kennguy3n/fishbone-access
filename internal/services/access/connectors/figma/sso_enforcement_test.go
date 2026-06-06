package figma

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func figmaSSOConfig() map[string]interface{} {
	return map[string]interface{}{"team_id": "t-1", "org_id": "org-1"}
}
func figmaSSOSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "figma-token"}
}

func TestFigma_CheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/organizations/org-1") {
			t.Errorf("path=%q; want suffix /organizations/org-1", r.URL.Path)
		}
		if r.Header.Get("X-Figma-Token") != "figma-token" {
			t.Errorf("token header=%q; want figma-token", r.Header.Get("X-Figma-Token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"org-1","name":"Acme","sso_required":true}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), figmaSSOConfig(), figmaSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Fatalf("enforced=false; want true (details=%q)", details)
	}
}

func TestFigma_CheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"org-1","name":"Acme","sso_required":false}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, _, err := c.CheckSSOEnforcement(context.Background(), figmaSSOConfig(), figmaSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Fatal("enforced=true; want false")
	}
}

func TestFigma_CheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if _, _, err := c.CheckSSOEnforcement(context.Background(), figmaSSOConfig(), figmaSSOSecrets()); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestFigma_CheckSSOEnforcement_MissingOrgID(t *testing.T) {
	c := New()
	cfg := map[string]interface{}{"team_id": "t-1"}
	if _, _, err := c.CheckSSOEnforcement(context.Background(), cfg, figmaSSOSecrets()); err == nil {
		t.Fatal("err = nil; want non-nil on missing org_id")
	}
}

func TestFigma_SatisfiesSSOEnforcementCheckerInterface(t *testing.T) {
	var _ interface {
		CheckSSOEnforcement(context.Context, map[string]interface{}, map[string]interface{}) (bool, string, error)
	} = New()
}
