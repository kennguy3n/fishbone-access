package google_workspace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRevokeUserSessions_HappyPath: 204 from /signOut means
// "sign-out propagated"; the connector returns nil.
func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seenPath, seenMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(t), "alice@example.com"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if seenMethod != http.MethodPost {
		t.Errorf("method=%q; want POST", seenMethod)
	}
	if !strings.HasSuffix(seenPath, "/users/alice@example.com/signOut") {
		t.Errorf("path=%q; want suffix /users/alice@example.com/signOut", seenPath)
	}
}

// TestRevokeUserSessions_NotFoundIsIdempotent: 404 from Google
// means the user is already gone — kill switch is
// idempotent.
func TestRevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(t), "alice@example.com"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil", err)
	}
}

// TestRevokeUserSessions_ValidationEmptyID: empty userExternalID
// returns immediately so the HTTP call is never issued.
func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err = nil; want validation error")
	}
}

// TestRevokeUserSessions_HTTPFailure: a 500 surfaces as a
// non-nil err.
func TestRevokeUserSessions_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(t), "alice@example.com"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}
