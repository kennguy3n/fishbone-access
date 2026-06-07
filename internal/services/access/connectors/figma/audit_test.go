package figma

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
		if !strings.HasPrefix(r.URL.Path, "/activity_logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("X-Figma-Token") == "" {
			t.Errorf("X-Figma-Token missing")
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"meta": map[string]interface{}{
					"events": []map[string]interface{}{
						{
							"id":         "evt-1",
							"event_type": "user.invited",
							"timestamp":  "2024-01-01T10:00:00.123Z",
							"actor": map[string]interface{}{
								"id":    "actor-1",
								"email": "admin@example.com",
							},
							"entity": map[string]interface{}{
								"id":   "user-9",
								"type": "user",
							},
							"context": map[string]interface{}{
								"ip_address": "203.0.113.1",
							},
						},
					},
				},
				"pagination": map[string]interface{}{
					"next_page": "cursor-2",
				},
			})
		case 1:
			call++
			if r.URL.Query().Get("cursor") != "cursor-2" {
				t.Errorf("cursor = %s", r.URL.Query().Get("cursor"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"meta": map[string]interface{}{
					"events": []map[string]interface{}{
						{
							"id":         "evt-2",
							"event_type": "file.viewed",
							"timestamp":  "2024-01-01T11:00:00Z",
							"actor": map[string]interface{}{
								"id": "actor-2",
							},
							"entity": map[string]interface{}{
								"id":   "file-77",
								"type": "file",
							},
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

func TestMapFigmaActivity_SkipsZeroTimestamp(t *testing.T) {
	e := &figmaActivityEvent{ID: "evt-1", EventType: "user.invited", Timestamp: "not-a-timestamp"}
	if got := mapFigmaActivity(e); got != nil {
		t.Fatalf("mapFigmaActivity with unparseable timestamp = %+v; want nil", got)
	}
	e.Timestamp = "2024-01-01T10:00:00Z"
	if got := mapFigmaActivity(e); got == nil {
		t.Fatal("mapFigmaActivity with valid timestamp = nil; want entry")
	}
}

func TestParseFigmaTime_NormalizesToUTC(t *testing.T) {
	for _, in := range []string{
		"2024-01-01T12:00:00+02:00",        // RFC3339 with offset
		"2024-01-01T12:00:00.500000+02:00", // RFC3339Nano with offset
		"1704106800",                       // Unix epoch seconds
	} {
		got := parseFigmaTime(in)
		if got.Location() != time.UTC {
			t.Errorf("parseFigmaTime(%q).Location() = %v; want UTC", in, got.Location())
		}
	}
}
