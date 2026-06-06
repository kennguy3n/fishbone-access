package ping_identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pingSessionConfig() map[string]interface{} {
	return map[string]interface{}{"environment_id": "env-1", "region": "NA"}
}
func pingSessionSecrets() map[string]interface{} {
	return map[string]interface{}{"client_id": "cid", "client_secret": "csecret"}
}

func pingTokenHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer"}`))
}

func TestPingIdentity_RevokeUserSessions_HappyPath(t *testing.T) {
	var sessionCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			pingTokenHandler(w, r)
			return
		}
		sessionCalled = true
		if r.Method != http.MethodDelete {
			t.Errorf("method=%q; want DELETE", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/environments/env-1/users/u123/sessions") {
			t.Errorf("path=%q; want suffix /v1/environments/env-1/users/u123/sessions", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer at-1" {
			t.Errorf("auth=%q; want Bearer at-1", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), pingSessionConfig(), pingSessionSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if !sessionCalled {
		t.Fatal("session endpoint not called")
	}
}

func TestPingIdentity_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			pingTokenHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), pingSessionConfig(), pingSessionSecrets(), "u123"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

func TestPingIdentity_RevokeUserSessions_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/as/token") {
			pingTokenHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), pingSessionConfig(), pingSessionSecrets(), "u123"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestPingIdentity_RevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), pingSessionConfig(), pingSessionSecrets(), ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}

func TestPingIdentity_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ interface {
		RevokeUserSessions(context.Context, map[string]interface{}, map[string]interface{}, string) error
	} = New()
}
