package microsoft

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seen *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "u-1"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if seen == nil || seen.Method != http.MethodPost {
		t.Fatalf("expected POST, got %+v", seen)
	}
	if !strings.HasSuffix(seen.URL.Path, "/users/u-1/revokeSignInSessions") {
		t.Errorf("path=%q; want suffix /users/u-1/revokeSignInSessions", seen.URL.Path)
	}
}

func TestRevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "u-1"); err != nil {
		t.Fatalf("404 should be idempotent, got %v", err)
	}
}

func TestRevokeUserSessions_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) httpDoer {
		return &serverFirstFakeClient{base: server.URL, http: server.Client()}
	}
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "u-1"); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err=nil; want validation error")
	}
}
