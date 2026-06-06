package front

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFront_RevokeUserSessions_HappyPath(t *testing.T) {
	var (
		mu       sync.Mutex
		bodySeen string
		methSeen string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing Bearer auth")
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		methSeen = r.Method
		bodySeen = string(b)
		mu.Unlock()
		if !strings.HasSuffix(r.URL.Path, "/teammates/tu-12345") {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "tu-12345"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if methSeen != http.MethodPatch {
		t.Errorf("method = %q; want PATCH", methSeen)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(bodySeen), &payload); err != nil {
		t.Fatalf("decode payload: %v (raw=%q)", err, bodySeen)
	}
	if payload["is_blocked"] != true {
		t.Errorf("is_blocked = %v; want true", payload["is_blocked"])
	}
}

func TestFront_RevokeUserSessions_NotFoundIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "tu-gone"); err != nil {
		t.Errorf("404 should be idempotent; got %v", err)
	}
}

func TestFront_RevokeUserSessions_EmptyRejected(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "userExternalID is required") {
		t.Errorf("err = %v; want validation error", err)
	}
}

func TestFront_RevokeUserSessions_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"_error":{"status":500}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "tu-1")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500", err)
	}
}

func TestFront_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ access.SessionRevoker = New()
}
