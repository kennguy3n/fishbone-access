package jira

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seenMethod, seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "557058:abc-1"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if seenMethod != http.MethodPost {
		t.Errorf("method=%q; want POST", seenMethod)
	}
	// The Atlassian Admin lifecycle-disable path. r.URL.Path is the
	// decoded form (':' is not percent-encoded by the test server),
	// so assert against the unescaped accountId.
	wantSuffix := "/users/557058:abc-1/manage/lifecycle/disable"
	if !strings.HasSuffix(seenPath, wantSuffix) {
		t.Errorf("path=%q; want suffix %q", seenPath, wantSuffix)
	}
	// Regression: we must NOT hit the destructive site-level Delete User endpoint.
	if strings.Contains(seenPath, "/rest/api/3/user") {
		t.Errorf("path=%q hit the destructive DELETE /rest/api/3/user endpoint; want admin lifecycle path", seenPath)
	}
}

func TestRevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "557058:abc-1"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

func TestRevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), validConfig(), validSecrets(), "557058:abc-1"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}
