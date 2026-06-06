package kareo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestKareoFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth header missing")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{
				"id":         "evt-1",
				"event_type": "user.created",
				"action":     "create",
				"timestamp":  "2024-09-01T10:00:00Z",
				"actor":      map[string]interface{}{"id": "u1", "email": "admin@example.com"},
				"target":     map[string]interface{}{"id": "u9", "type": "user"},
			}},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
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

func TestKareoFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestKareoFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}

// TestMapKareoAuditEvent_DropsEmptyID is a regression guard: events with an
// empty or whitespace-only id must be dropped rather than emitted with an
// empty EventID, which would break downstream dedup/indexing. This matches the
// empty-ID guard the sibling mappers (ironclad/jasper/keeper/klaviyo) apply.
func TestMapKareoAuditEvent_DropsEmptyID(t *testing.T) {
	got := mapKareoAuditEvent(&kareoAuditEvent{
		ID:        "  ",
		EventType: "user.login",
		Timestamp: "2024-01-02T03:04:05Z",
	})
	if got != nil {
		t.Fatalf("mapKareoAuditEvent with empty id = %+v; want nil (empty EventID must not reach the audit pipeline)", got)
	}

	valid := mapKareoAuditEvent(&kareoAuditEvent{
		ID:        "evt-1",
		EventType: "user.login",
		Timestamp: "2024-01-02T03:04:05Z",
	})
	if valid == nil {
		t.Fatal("mapKareoAuditEvent with a valid id returned nil; want a mapped entry")
	}
	if valid.EventID != "evt-1" {
		t.Fatalf("EventID = %q; want %q", valid.EventID, "evt-1")
	}
}

// TestKareoFetchAccessAuditLogs_EmitsPerPage proves the connector invokes the
// handler once per provider page (AccessAuditor contract) instead of buffering
// every page into a single batch. See the ironclad sibling for rationale.
func TestKareoFetchAccessAuditLogs_EmitsPerPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			rows := make([]map[string]interface{}, kareoAuditPageSize)
			for i := range rows {
				rows[i] = map[string]interface{}{
					"id":         fmt.Sprintf("evt-%d", i),
					"event_type": "chart.view",
					"timestamp":  time.Date(2024, 9, 1, 0, 0, i, 0, time.UTC).Format(time.RFC3339),
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": rows})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{{
			"id":         "evt-last",
			"event_type": "chart.view",
			"timestamp":  "2024-09-02T10:00:00Z",
		}}})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var calls, total int
	var last time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			calls++
			total += len(batch)
			if n.Before(last) {
				t.Errorf("nextSince regressed: %s < %s", n, last)
			}
			last = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls < 2 {
		t.Fatalf("handler called %d time(s); want one call per page (>=2)", calls)
	}
	if total != kareoAuditPageSize+1 {
		t.Fatalf("total entries = %d; want %d", total, kareoAuditPageSize+1)
	}
	if !last.Equal(time.Date(2024, 9, 2, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("final nextSince = %s; want 2024-09-02T10:00:00Z", last)
	}
}
