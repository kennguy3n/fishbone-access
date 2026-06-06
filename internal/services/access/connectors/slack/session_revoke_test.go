package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seenForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/admin.users.session.reset") {
			t.Errorf("path=%q; want suffix /admin.users.session.reset", r.URL.Path)
		}
		_ = r.ParseForm()
		seenForm = r.PostForm.Encode()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "U123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !strings.Contains(seenForm, "user_id=U123") {
		t.Errorf("form=%q; want user_id=U123", seenForm)
	}
}

func TestRevokeUserSessions_UserNotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"user_not_found"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "U123"); err != nil {
		t.Fatalf("user_not_found should be idempotent: %v", err)
	}
}

func TestRevokeUserSessions_MissingScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"missing_scope"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "U123"); err == nil {
		t.Fatal("err=nil; want non-nil on missing_scope")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err=nil; want validation error")
	}
}
