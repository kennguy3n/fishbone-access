package heroku

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func herokuAuditConfig() map[string]interface{} {
	return map[string]interface{}{"team_name": "acme-enterprise"}
}
func herokuAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "tok-abcdefgh"}
}

func TestHerokuFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enterprise-accounts/acme-enterprise/events" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(r.Header.Get("Accept"), "audit-trail") {
			t.Errorf("accept = %q", r.Header.Get("Accept"))
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":         "evt-1",
				"type":       "membership",
				"action":     "add",
				"created_at": "2024-06-01T11:00:00Z",
				"actor":      map[string]string{"id": "u-1", "email": "admin@example.com"},
				"app":        map[string]string{"id": "app-1", "name": "production"},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), herokuAuditConfig(), herokuAuditSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].TargetExternalID != "app-1" || collected[0].TargetType != "app" {
		t.Errorf("entry = %+v", collected[0])
	}
	if !nextSince.Equal(time.Date(2024, 6, 1, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestHerokuFetchAccessAuditLogs_NotAvailableMissingTeam(t *testing.T) {
	c := New()
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, herokuAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestHerokuFetchAccessAuditLogs_NotAvailableHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), herokuAuditConfig(), herokuAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestHerokuFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), herokuAuditConfig(), herokuAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
