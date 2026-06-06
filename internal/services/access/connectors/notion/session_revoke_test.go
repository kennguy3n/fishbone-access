package notion

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeUserSessions_HappyPath(t *testing.T) {
	var seenMethod, seenPath, seenVer string
	var seenBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenVer = r.Header.Get("Notion-Version")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seenBody)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if seenMethod != http.MethodPatch {
		t.Errorf("method=%q; want PATCH", seenMethod)
	}
	if !strings.HasSuffix(seenPath, "/v1/users/user-1") {
		t.Errorf("path=%q; want suffix /v1/users/user-1", seenPath)
	}
	if seenVer == "" {
		t.Error("Notion-Version header not set")
	}
	if got, _ := seenBody["status"].(string); got != "deactivated" {
		t.Errorf("status=%q; want deactivated", got)
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
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err != nil {
		t.Fatalf("RevokeUserSessions on 404: %v; want nil (idempotent)", err)
	}
}

func TestRevokeUserSessions_ObjectNotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"object_not_found","message":"user not found"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err != nil {
		t.Fatalf("RevokeUserSessions on object_not_found: %v; want nil (idempotent)", err)
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
	if err := c.RevokeUserSessions(context.Background(), nil, validSecrets(), "user-1"); err == nil {
		t.Fatal("err = nil; want non-nil on 500")
	}
}

func TestRevokeUserSessions_ValidationEmptyID(t *testing.T) {
	c := New()
	if err := c.RevokeUserSessions(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("err = nil; want validation error on empty userExternalID")
	}
}
