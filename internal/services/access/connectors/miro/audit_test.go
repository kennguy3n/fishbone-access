package miro

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
		if !strings.HasPrefix(r.URL.Path, "/audit/logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth missing")
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":        "evt-1",
						"event":     "user.invited",
						"createdAt": "2024-01-01T10:00:00.500Z",
						"createdBy": map[string]interface{}{
							"id":    "actor-1",
							"email": "admin@example.com",
						},
						"object": map[string]interface{}{
							"id":   "user-9",
							"type": "user",
						},
						"context": map[string]interface{}{
							"ip": "203.0.113.1",
						},
					},
				},
				"cursor": "cursor-2",
			})
		case 1:
			call++
			if r.URL.Query().Get("cursor") != "cursor-2" {
				t.Errorf("cursor = %s", r.URL.Query().Get("cursor"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":        "evt-2",
						"event":     "board.shared",
						"createdAt": "2024-01-01T11:00:00Z",
						"createdBy": map[string]interface{}{
							"id": "actor-2",
						},
						"object": map[string]interface{}{
							"id":   "board-77",
							"type": "board",
						},
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
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].EventType != "user.invited" || collected[0].TargetExternalID != "user-9" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

// TestFetchAccessAuditLogs_SkipsUnparseableTimestamp is a regression test for
// the missing zero-timestamp guard: an event whose createdAt is empty/garbage
// must be dropped (matching the sibling connectors) rather than flowing into
// the audit pipeline with a zero time.Time. The valid sibling event in the same
// page must still be emitted.
func TestFetchAccessAuditLogs_SkipsUnparseableTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":        "evt-bad",
					"event":     "user.invited",
					"createdAt": "not-a-timestamp",
					"createdBy": map[string]interface{}{"id": "actor-1"},
					"object":    map[string]interface{}{"id": "user-9", "type": "user"},
				},
				{
					"id":        "evt-good",
					"event":     "board.shared",
					"createdAt": "2024-01-01T11:00:00Z",
					"createdBy": map[string]interface{}{"id": "actor-2"},
					"object":    map[string]interface{}{"id": "board-77", "type": "board"},
				},
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
		t.Fatalf("len = %d; want 1 (bad-timestamp event dropped)", len(collected))
	}
	if collected[0].EventID != "evt-good" {
		t.Fatalf("kept %q; want evt-good", collected[0].EventID)
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
