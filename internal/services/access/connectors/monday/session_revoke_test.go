package monday

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func mondaySessionConfig() map[string]interface{}  { return map[string]interface{}{} }
func mondaySessionSecrets() map[string]interface{} { return map[string]interface{}{"api_token": "tok-1"} }

func TestMonday_RevokeUserSessions_HappyPath(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "deactivate_users(user_ids: [42]") {
			t.Errorf("body=%q; want deactivate_users(user_ids: [42] ...)", string(body))
		}
		_, _ = w.Write([]byte(`{"data":{"deactivate_users":[{"id":"42"}]}}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), mondaySessionConfig(), mondaySessionSecrets(), "42"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if calls != 1 {
		t.Errorf("got %d calls; want 1", calls)
	}
}

func TestMonday_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"User not found"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), mondaySessionConfig(), mondaySessionSecrets(), "999"); err != nil {
		t.Errorf("err=%v; want nil for idempotent not-found", err)
	}
}

func TestMonday_RevokeUserSessions_AlreadyDeactivatedIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"User already deactivated"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	if err := c.RevokeUserSessions(context.Background(), mondaySessionConfig(), mondaySessionSecrets(), "42"); err != nil {
		t.Errorf("err=%v; want nil for idempotent already-deactivated", err)
	}
}

func TestMonday_RevokeUserSessions_GraphQLErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"permission denied"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	err := c.RevokeUserSessions(context.Background(), mondaySessionConfig(), mondaySessionSecrets(), "42")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("err=%v; want graphql error surfaced", err)
	}
}

func TestMonday_RevokeUserSessions_500Surfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	err := c.RevokeUserSessions(context.Background(), mondaySessionConfig(), mondaySessionSecrets(), "42")
	if err == nil {
		t.Error("err = nil; want non-nil for 500")
	}
}

func TestMonday_RevokeUserSessions_EmptyIDIsValidationError(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), mondaySessionConfig(), mondaySessionSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("err=%v; want validation error for empty id", err)
	}
}

func TestMonday_RevokeUserSessions_NonNumericIDIsValidationError(t *testing.T) {
	c := New()
	err := c.RevokeUserSessions(context.Background(), mondaySessionConfig(), mondaySessionSecrets(), "abc")
	if err == nil || !strings.Contains(err.Error(), "numeric") {
		t.Errorf("err=%v; want numeric-id validation error", err)
	}
}

func TestMonday_SatisfiesSessionRevokerInterface(_ *testing.T) {
	var _ access.SessionRevoker = New()
}
