package clickup

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

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/team/team-1/audit") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth missing")
		}
		switch call {
		case 0:
			call++
			if r.URL.Query().Get("page") != "0" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			rows := make([]map[string]interface{}, 0, 100)
			rows = append(rows, map[string]interface{}{
				"id":         "evt-1",
				"event_type": "WorkspaceUserInvited",
				"date":       "2024-01-01T10:00:00Z",
				"user":       map[string]interface{}{"id": 42, "email": "admin@example.com"},
				"target":     map[string]interface{}{"id": "u-9", "type": "user"},
			})
			for i := 1; i < 100; i++ {
				rows = append(rows, map[string]interface{}{
					"id":         "evt-filler",
					"event_type": "noop",
					"date":       "2024-01-01T10:30:00Z",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": rows})
		case 1:
			call++
			if r.URL.Query().Get("page") != "1" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"events": []map[string]interface{}{
					{
						"id":         "evt-2",
						"event_type": "SpaceSharedWithUser",
						"date":       "2024-01-01T11:00:00Z",
						"user":       map[string]interface{}{"id": 43},
						"target":     map[string]interface{}{"id": "sp-77", "type": "space"},
					},
				},
			})
		default:
			t.Errorf("unexpected call %d", call)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) < 2 {
		t.Fatalf("len = %d, want >=2", len(collected))
	}
	if collected[0].EventType != "WorkspaceUserInvited" || collected[0].TargetExternalID != "u-9" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

// TestFetchAccessAuditLogs_CapsPages guards the max-page bound: a provider
// that keeps returning a full page (e.g. a date_from window that never
// advances) must not drive an unbounded request loop. The connector must
// stop after clickupAuditMaxPages requests. Without the cap the loop only
// ends once the server stops returning full pages (well past the cap), so
// the request count would exceed clickupAuditMaxPages and fail this test.
func TestFetchAccessAuditLogs_CapsPages(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		// Return a full page until well past the cap so the only thing
		// that can stop iteration is the connector's own bound; the
		// short final page only guards against a hang if the cap is gone.
		n := clickupAuditPageSize
		if requests > clickupAuditMaxPages+50 {
			n = 1
		}
		rows := make([]map[string]interface{}, 0, n)
		for i := 0; i < n; i++ {
			rows = append(rows, map[string]interface{}{
				"id":         "evt",
				"event_type": "WorkspaceUserInvited",
				"date":       "2024-01-01T10:00:00Z",
				"user":       map[string]interface{}{"id": 1, "email": "a@example.com"},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": rows})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if requests != clickupAuditMaxPages {
		t.Fatalf("requests = %d, want %d (pagination must stop at the cap)", requests, clickupAuditMaxPages)
	}
}

// TestFetchAccessAuditLogs_DropsUnparseableTimestamp guards against
// emitting audit entries with a zero (0001-01-01) timestamp. Events
// whose `date` is absent or unparseable must be dropped rather than
// forwarded, otherwise they poison the watermark cursor and surface a
// bogus timestamp downstream.
func TestFetchAccessAuditLogs_DropsUnparseableTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"events": []map[string]interface{}{
				{"id": "evt-good", "event_type": "WorkspaceUserInvited", "date": "2024-01-01T10:00:00Z"},
				{"id": "evt-bad", "event_type": "WorkspaceUserInvited", "date": "not-a-timestamp"},
				{"id": "evt-empty", "event_type": "WorkspaceUserInvited", "date": ""},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d, want 1 (zero-timestamp events must be dropped)", len(collected))
	}
	if collected[0].EventID != "evt-good" {
		t.Errorf("EventID = %s, want evt-good", collected[0].EventID)
	}
	for _, e := range collected {
		if e.Timestamp.IsZero() {
			t.Errorf("emitted entry with zero timestamp: %+v", e)
		}
	}
}
