package asana

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestAsana_RevokeUserSessions_HappyPath(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusNoContent, &captured)
	conn := withAsanaSCIMTestServer(t, srv)

	if err := conn.RevokeUserSessions(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), "u-12345"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("captured = %d; want 1", len(captured))
	}
	if captured[0].Method != http.MethodDelete {
		t.Errorf("method = %q; want DELETE", captured[0].Method)
	}
	if !strings.HasSuffix(captured[0].Path, "/scim/Users/u-12345") {
		t.Errorf("path = %q", captured[0].Path)
	}
	if captured[0].Auth != "Bearer asana-token" {
		t.Errorf("auth = %q", captured[0].Auth)
	}
}

func TestAsana_RevokeUserSessions_NotFoundIsIdempotent(t *testing.T) {
	var captured []scimRoundtrip
	srv := newAsanaSCIMTestServer(t, http.StatusNotFound, &captured)
	conn := withAsanaSCIMTestServer(t, srv)
	if err := conn.RevokeUserSessions(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), "u-gone"); err != nil {
		t.Errorf("404 should be idempotent; got %v", err)
	}
}

func TestAsana_RevokeUserSessions_EmptyRejected(t *testing.T) {
	conn := New()
	err := conn.RevokeUserSessions(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), "")
	if err == nil || !strings.Contains(err.Error(), "userExternalID is required") {
		t.Errorf("err = %v; want validation error", err)
	}
}

func TestAsana_RevokeUserSessions_ServerErrorPropagates(t *testing.T) {
	var mu sync.Mutex
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		called++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}))
	t.Cleanup(srv.Close)
	conn := New()
	conn.urlOverride = srv.URL
	prev := SetSCIMClientForTest(access.NewSCIMClient().WithHTTPClient(srv.Client()))
	t.Cleanup(func() { SetSCIMClientForTest(prev) })
	err := conn.RevokeUserSessions(context.Background(), asanaSCIMConfig(), asanaSCIMSecrets(), "u-1")
	if err == nil {
		t.Errorf("err = nil; want server error")
	}
	if called != 1 {
		t.Errorf("called = %d; want 1", called)
	}
}

func TestAsana_SatisfiesSessionRevokerInterface(t *testing.T) {
	var _ access.SessionRevoker = New()
}
