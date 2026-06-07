package basecamp

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

func basecampAuditConfig() map[string]interface{} {
	return map[string]interface{}{"account_id": "123"}
}
func basecampAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "tok"}
}

func TestBasecampFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/events.json") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
			"id":         int64(1001),
			"action":     "person.created",
			"created_at": "2024-09-01T10:00:00.000Z",
			"creator":    map[string]interface{}{"id": int64(7), "name": "Admin", "email_address": "admin@example.com"},
			"recording":  map[string]interface{}{"id": int64(42), "type": "Person", "title": "Jane"},
		}})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), basecampAuditConfig(), basecampAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].ActorEmail != "admin@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

// TestBasecampFetchAccessAuditLogs_FollowsLinkHeader proves the walk
// paginates via the RFC 5988 rel="next" Link header rather than a
// page-size sentinel: page 1 returns a single event (fewer than the old
// hardcoded 50) yet advertises a next page, and the second event is only
// reachable by following the Link header.
func TestBasecampFetchAccessAuditLogs_FollowsLinkHeader(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id":         int64(1002),
				"action":     "person.updated",
				"created_at": "2024-09-02T11:00:00.000Z",
				"creator":    map[string]interface{}{"id": int64(8), "name": "Ops", "email_address": "ops@example.com"},
				"recording":  map[string]interface{}{"id": int64(43), "type": "Person", "title": "Joe"},
			}})
			return
		}
		w.Header().Set("Link", "<"+srvURL+"/events.json?page=2>; rel=\"next\"")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
			"id":         int64(1001),
			"action":     "person.created",
			"created_at": "2024-09-01T10:00:00.000Z",
			"creator":    map[string]interface{}{"id": int64(7), "name": "Admin", "email_address": "admin@example.com"},
			"recording":  map[string]interface{}{"id": int64(42), "type": "Person", "title": "Jane"},
		}})
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), basecampAuditConfig(), basecampAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("expected 2 events across two pages, got %d: %+v", len(collected), collected)
	}
	if collected[1].ActorEmail != "ops@example.com" {
		t.Errorf("second-page event not collected: %+v", collected[1])
	}
}

func TestBasecampFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), basecampAuditConfig(), basecampAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestBasecampFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), basecampAuditConfig(), basecampAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
