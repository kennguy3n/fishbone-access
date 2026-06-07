package gitlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gitlabSessionConfig() map[string]interface{} {
	return map[string]interface{}{"group_id": "g1"}
}
func gitlabSessionSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "gl-token"}
}

func TestGitLab_RevokeUserSessions_HappyPath(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete {
			t.Errorf("method=%q; want DELETE", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/v4/personal_access_tokens") {
			t.Errorf("path=%q; want suffix /api/v4/personal_access_tokens", r.URL.Path)
		}
		if r.URL.Query().Get("user_id") != "u123" {
			t.Errorf("user_id=%q; want u123", r.URL.Query().Get("user_id"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), gitlabSessionConfig(), gitlabSessionSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !called {
		t.Fatal("upstream not called")
	}
}

func TestGitLab_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), gitlabSessionConfig(), gitlabSessionSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

func TestGitLab_RevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), gitlabSessionConfig(), gitlabSessionSecrets(), "u123"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestGitLab_RevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), gitlabSessionConfig(), gitlabSessionSecrets(), ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}

func TestGitLab_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ interface {
		RevokeUserSessions(context.Context, map[string]interface{}, map[string]interface{}, string) error
	} = New()
}
