package docker_hub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestDockerHub_RevokeUserSessions_HappyPath(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/users/login" {
			_, _ = w.Write([]byte(`{"token":"jwt-test-token"}`))
			return
		}
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q; want DELETE", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v2/orgs/acme/members/alice") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "JWT ") {
			t.Errorf("missing JWT auth")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "Alice"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if len(seen) != 1 {
		t.Errorf("seen = %v; want one DELETE call", seen)
	}
}

func TestDockerHub_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/users/login" {
			_, _ = w.Write([]byte(`{"token":"jwt-test-token"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "gone"); err != nil {
		t.Errorf("404 should be idempotent; got %v", err)
	}
}

func TestDockerHub_RevokeUserSessions_EmptyRejected(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "userExternalID is required") {
		t.Errorf("err = %v; want validation error", err)
	}
}

func TestDockerHub_RevokeUserSessions_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/users/login" {
			_, _ = w.Write([]byte(`{"token":"jwt-test-token"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "alice")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestDockerHub_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ access.SessionRevoker = New()
}
