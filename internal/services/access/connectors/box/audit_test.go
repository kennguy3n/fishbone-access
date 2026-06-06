package box

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
		if r.URL.Path != "/2.0/events" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("stream_type") != "admin_logs" {
			t.Errorf("stream_type = %s", r.URL.Query().Get("stream_type"))
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth missing")
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"chunk_size":           1,
				"next_stream_position": "pos-2",
				"entries": []map[string]interface{}{
					{
						"type":       "event",
						"event_id":   "evt-1",
						"event_type": "USER_LOGIN",
						"created_at": "2024-01-01T10:00:00Z",
						"created_by": map[string]interface{}{
							"id":    "actor-1",
							"login": "admin@example.com",
						},
						"source": map[string]interface{}{
							"id":   "user-9",
							"type": "user",
						},
						"ip_address": "203.0.113.1",
					},
				},
			})
		case 1:
			call++
			if r.URL.Query().Get("stream_position") != "pos-2" {
				t.Errorf("stream_position = %s", r.URL.Query().Get("stream_position"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"chunk_size":           1,
				"next_stream_position": "pos-2", // unchanged => terminate
				"entries": []map[string]interface{}{
					{
						"type":       "event",
						"event_id":   "evt-2",
						"event_type": "ITEM_SHARED",
						"created_at": "2024-01-01T11:00:00Z",
						"created_by": map[string]interface{}{
							"id": "actor-2",
						},
						"source": map[string]interface{}{
							"id":   "file-77",
							"type": "file",
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
	if collected[0].EventType != "USER_LOGIN" || collected[0].TargetExternalID != "user-9" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].EventType != "ITEM_SHARED" || strings.TrimSpace(collected[1].TargetExternalID) != "file-77" {
		t.Errorf("entry 1 = %+v", collected[1])
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
