package auth0

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seenPath, seenMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			seenPath = r.URL.Path
			seenMethod = r.Method
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "auth0|user-1"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if seenMethod != http.MethodDelete {
		t.Errorf("method=%q; want DELETE", seenMethod)
	}
	if !strings.HasSuffix(seenPath, "/api/v2/users/auth0|user-1/sessions") {
		t.Errorf("path=%q; want suffix /api/v2/users/auth0|user-1/sessions", seenPath)
	}
}

func TestRevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "auth0|user-1"); err != nil {
		t.Fatalf("404 should be idempotent: %v", err)
	}
}

func TestRevokeUserSessions_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "auth0|user-1"); err == nil {
		t.Fatal("err=nil; want non-nil on 403")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err=nil; want validation error")
	}
}
