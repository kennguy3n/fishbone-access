package datadog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func datadogRevokeConfig() map[string]interface{} { return map[string]interface{}{} }
func datadogRevokeSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "k", "application_key": "ak"}
}

func TestDatadog_RevokeUserSessions_HappyPath(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPatch {
			t.Errorf("method=%q; want PATCH", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/v2/users/u123") {
			t.Errorf("path=%q; want suffix /api/v2/users/u123", r.URL.Path)
		}
		if r.Header.Get("DD-API-KEY") != "k" || r.Header.Get("DD-APPLICATION-KEY") != "ak" {
			t.Errorf("missing auth headers")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), datadogRevokeConfig(), datadogRevokeSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !called {
		t.Fatal("upstream not called")
	}
}

func TestDatadog_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), datadogRevokeConfig(), datadogRevokeSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

func TestDatadog_RevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), datadogRevokeConfig(), datadogRevokeSecrets(), "u123"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestDatadog_RevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), datadogRevokeConfig(), datadogRevokeSecrets(), ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}

func TestDatadog_SatisfiesSessionRevokerInterface(_ *testing.T) {
	var _ access.SessionRevoker = (*DatadogAccessConnector)(nil)
}
