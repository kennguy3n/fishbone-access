package gitlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gitlabSSOConfig() map[string]interface{} { return map[string]interface{}{"group_id": "g1"} }
func gitlabSSOSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "gl-token"}
}

func TestGitLab_CheckSSOEnforcement_Enforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/v4/application/settings") {
			t.Errorf("path=%q; want suffix /api/v4/application/settings", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"password_authentication_enabled_for_web":false,"password_authentication_enabled_for_git":false}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), gitlabSSOConfig(), gitlabSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if !enforced {
		t.Fatalf("enforced=false; want true (details=%q)", details)
	}
	if details == "" {
		t.Fatal("details empty; want non-empty hint")
	}
}

func TestGitLab_CheckSSOEnforcement_NotEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"password_authentication_enabled_for_web":true,"password_authentication_enabled_for_git":false}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	enforced, details, err := c.CheckSSOEnforcement(context.Background(), gitlabSSOConfig(), gitlabSSOSecrets())
	if err != nil {
		t.Fatalf("CheckSSOEnforcement: %v", err)
	}
	if enforced {
		t.Fatalf("enforced=true; want false (details=%q)", details)
	}
}

func TestGitLab_CheckSSOEnforcement_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if _, _, err := c.CheckSSOEnforcement(context.Background(), gitlabSSOConfig(), gitlabSSOSecrets()); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestGitLab_SatisfiesSSOEnforcementCheckerInterface(t *testing.T) {
	var _ interface {
		CheckSSOEnforcement(context.Context, map[string]interface{}, map[string]interface{}) (bool, string, error)
	} = New()
}
