package notion

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
		if r.URL.Path != "/v1/audit_log" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Notion-Version") == "" {
			t.Errorf("Notion-Version header missing")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"object":      "list",
				"has_more":    true,
				"next_cursor": "cursor-2",
				"results": []map[string]interface{}{
					{
						"id":         "evt-1",
						"event_type": "user.invited",
						"timestamp":  "2024-01-01T10:00:00.500Z",
						"actor": map[string]interface{}{
							"id":    "actor-1",
							"email": "admin@example.com",
						},
						"target": map[string]interface{}{
							"id":   "user-9",
							"type": "user",
						},
						"ip_address": "203.0.113.1",
					},
				},
			})
		case 1:
			call++
			if r.URL.Query().Get("start_cursor") != "cursor-2" {
				t.Errorf("start_cursor = %s", r.URL.Query().Get("start_cursor"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"object":   "list",
				"has_more": false,
				"results": []map[string]interface{}{
					{
						"id":         "evt-2",
						"event_type": "page.shared",
						"timestamp":  "2024-01-01T11:00:00Z",
						"actor": map[string]interface{}{
							"id": "actor-2",
						},
						"target": map[string]interface{}{
							"id":   "page-77",
							"type": "page",
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
	err := c.FetchAccessAuditLogs(context.Background(), nil, validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error {
			if partitionKey != access.DefaultAuditPartition {
				t.Errorf("partitionKey = %q", partitionKey)
			}
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
	if collected[0].Timestamp.IsZero() {
		t.Errorf("entry 0 timestamp is zero")
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
	err := c.FetchAccessAuditLogs(context.Background(), nil, validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"object":"error","code":"unsupported_audit_log","message":"not enabled"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), nil, validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestMapNotionAuditEvent_DropsUnparseableTimestamp(t *testing.T) {
	// A non-empty but unparseable timestamp must not produce a zero-timestamp entry.
	e := &notionAuditEvent{ID: "evt-1", EventType: "user.invited", Timestamp: "01/02/2024"}
	if got := mapNotionAuditEvent(e); got != nil {
		t.Fatalf("expected nil for unparseable timestamp, got %+v", got)
	}
}
