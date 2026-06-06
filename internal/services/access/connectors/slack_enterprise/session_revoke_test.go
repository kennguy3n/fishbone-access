package slack_enterprise

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func slackEntSessionConfig() map[string]interface{} { return map[string]interface{}{} }
func slackEntSessionSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "xoxp-token"}
}

func TestSlackEnterprise_RevokeUserSessions_HappyPath(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			t.Errorf("method=%q; want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/admin.users.session.reset") {
			t.Errorf("path=%q; want suffix /api/admin.users.session.reset", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer xoxp-token" {
			t.Errorf("auth=%q; want Bearer xoxp-token", r.Header.Get("Authorization"))
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if r.Form.Get("user") != "U123" {
			t.Errorf("user=%q; want U123", r.Form.Get("user"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), slackEntSessionConfig(), slackEntSessionSecrets(), "U123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !called {
		t.Fatal("upstream not called")
	}
}

func TestSlackEnterprise_RevokeUserSessions_UserNotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"user_not_found"}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), slackEntSessionConfig(), slackEntSessionSecrets(), "U123"); err != nil {
		t.Fatalf("RevokeUserSessions on user_not_found: %v; want nil (idempotent)", err)
	}
}

func TestSlackEnterprise_RevokeUserSessions_ErrorPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"not_authed"}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), slackEntSessionConfig(), slackEntSessionSecrets(), "U123"); err == nil {
		t.Fatal("err = nil; want non-nil on ok=false")
	}
}

func TestSlackEnterprise_RevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), slackEntSessionConfig(), slackEntSessionSecrets(), "U123"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestSlackEnterprise_RevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), slackEntSessionConfig(), slackEntSessionSecrets(), ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}

func TestSlackEnterprise_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ interface {
		RevokeUserSessions(context.Context, map[string]interface{}, map[string]interface{}, string) error
	} = New()
}
