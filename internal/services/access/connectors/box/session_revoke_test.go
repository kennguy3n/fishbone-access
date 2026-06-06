package box

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func boxSessionConfig() map[string]interface{} { return map[string]interface{}{} }
func boxSessionSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "box-token"}
}

func TestBox_RevokeUserSessions_HappyPath(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete {
			t.Errorf("method=%q; want DELETE", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/2.0/users/u123/sessions") {
			t.Errorf("path=%q; want suffix /2.0/users/u123/sessions", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer box-token" {
			t.Errorf("auth=%q; want Bearer box-token", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), boxSessionConfig(), boxSessionSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !called {
		t.Fatal("upstream not called")
	}
}

func TestBox_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), boxSessionConfig(), boxSessionSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

func TestBox_RevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), boxSessionConfig(), boxSessionSecrets(), "u123"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestBox_RevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), boxSessionConfig(), boxSessionSecrets(), ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}

func TestBox_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ interface {
		RevokeUserSessions(context.Context, map[string]interface{}, map[string]interface{}, string) error
	} = New()
}
