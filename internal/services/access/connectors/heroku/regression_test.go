package heroku

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: team names containing URL-sensitive characters must be
// percent-encoded so the HTTP path is well-formed.  Before the fix,
// a team name like "a/b" produced "/teams/a/b/members" (extra segment)
// instead of "/teams/a%2Fb/members".

func TestConnect_TeamNameEscaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/teams/a%2Fb"
		if got := r.URL.EscapedPath(); got != want {
			t.Errorf("path = %s; want %s", got, want)
		}
		_, _ = w.Write([]byte(`{"id":"t1","name":"a/b"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), map[string]interface{}{"team_name": "a/b"}, validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestSyncIdentities_TeamNameEscaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/teams/a%2Fb/members"
		if got := r.URL.EscapedPath(); got != want {
			t.Errorf("path = %s; want %s", got, want)
		}
		_, _ = w.Write([]byte(`[{"id":"m1","email":"a@b.com","role":"admin","user":{"id":"u1","email":"a@b.com","name":"A"}}]`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), map[string]interface{}{"team_name": "a/b"}, validSecrets(), "", func([]*access.Identity, string) error { return nil })
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
}

func TestCountIdentities_TeamNameEscaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/teams/a%2Fb/members"
		if got := r.URL.EscapedPath(); got != want {
			t.Errorf("path = %s; want %s", got, want)
		}
		_, _ = w.Write([]byte(`[{"id":"m1","email":"a@b.com","role":"admin","user":{"id":"u1","email":"a@b.com"}}]`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	n, err := c.CountIdentities(context.Background(), map[string]interface{}{"team_name": "a/b"}, validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d; want 1", n)
	}
}

func TestFetchAuditLogs_EnterpriseEscaped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.EscapedPath(), "/enterprise-accounts/a%2Fb/events") {
			t.Errorf("path = %s; want /enterprise-accounts/a%%2Fb/events", r.URL.EscapedPath())
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":         "evt-1",
				"type":       "membership",
				"action":     "add",
				"created_at": "2024-06-01T11:00:00Z",
				"actor":      map[string]string{"id": "u-1", "email": "a@b.com"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(),
		map[string]interface{}{"team_name": "a/b"},
		validSecrets(),
		map[string]time.Time{},
		func([]*access.AuditLogEntry, time.Time, string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
}
