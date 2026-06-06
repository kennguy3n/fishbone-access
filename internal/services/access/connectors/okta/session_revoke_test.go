package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRevokeUserSessions_HappyPath: a 204 from Okta is "every
// session terminated" — the connector returns nil and the leaver
// flow proceeds to the next layer.
func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete {
			t.Errorf("method=%q; want DELETE", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/users/u123/sessions") {
			t.Errorf("path=%q; want suffix /users/u123/sessions", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c := New()
	c.urlOverride = server.URL
	cfg, sec := newOktaConfigSecrets(server.URL)
	if err := c.RevokeUserSessions(context.Background(), cfg, sec, "u123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !called {
		t.Fatal("upstream not called")
	}
}

// TestRevokeUserSessions_NotFoundIsIdempotent: 404 means the user
// is already gone — the kill switch is idempotent and reports
// success so the leaver flow does not retry forever.
func TestRevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	c := New()
	c.urlOverride = server.URL
	cfg, sec := newOktaConfigSecrets(server.URL)
	if err := c.RevokeUserSessions(context.Background(), cfg, sec, "u123"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

// TestRevokeUserSessions_HTTPFailure: a 500 surfaces as a non-nil
// err so the JML caller can log it but continue the leaver flow.
func TestRevokeUserSessions_HTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer server.Close()
	c := New()
	c.urlOverride = server.URL
	cfg, sec := newOktaConfigSecrets(server.URL)
	if err := c.RevokeUserSessions(context.Background(), cfg, sec, "u123"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

// TestRevokeUserSessions_ValidationEmptyID: empty userExternalID
// is a programming error in the JML flow; the connector returns
// immediately so the upstream HTTP call is never issued.
func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}
