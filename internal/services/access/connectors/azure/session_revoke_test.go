package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestAzure_RevokeUserSessions_HappyPath(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Method != http.MethodPost {
			t.Errorf("method = %q; want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/users/u-1/revokeSignInSessions") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing auth header")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "u-1"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if called != 1 {
		t.Errorf("called = %d; want 1", called)
	}
}

func TestAzure_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "u-gone"); err != nil {
		t.Errorf("404 should be idempotent success; got %v", err)
	}
}

func TestAzure_RevokeUserSessions_EmptyUserRejected(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "userExternalID is required") {
		t.Errorf("err = %v; want validation error", err)
	}
}

func TestAzure_RevokeUserSessions_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"InternalServerError"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestAzure_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ access.SessionRevoker = New()
}
