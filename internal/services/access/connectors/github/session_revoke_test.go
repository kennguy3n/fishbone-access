package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seenPath, seenMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "alice"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if seenMethod != http.MethodDelete {
		t.Errorf("method=%q; want DELETE", seenMethod)
	}
	if !strings.HasSuffix(seenPath, "/orgs/acme/memberships/alice") {
		t.Errorf("path=%q; want suffix /orgs/acme/memberships/alice", seenPath)
	}
}

func TestRevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "alice"); err != nil {
		t.Fatalf("404 should be idempotent: %v", err)
	}
}

func TestRevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "alice"); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err=nil; want validation error")
	}
}
