package salesforce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRevokeUserSessions_DeletesEachActiveSession(t *testing.T) {
	var deleteCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/query"):
			_, _ = w.Write([]byte(`{"records":[{"Id":"s1"},{"Id":"s2"}]}`))
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/AuthSession/"):
			atomic.AddInt32(&deleteCount, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "005xxxx"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if atomic.LoadInt32(&deleteCount) != 2 {
		t.Errorf("deleteCount=%d; want 2", deleteCount)
	}
}

func TestRevokeUserSessions_EmptySessionListIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "005xxxx"); err != nil {
		t.Fatalf("empty list should be idempotent: %v", err)
	}
}

func TestRevokeUserSessions_ListHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "005xxxx"); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err=nil; want validation error")
	}
}
