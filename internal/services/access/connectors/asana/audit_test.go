package asana

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
		if !strings.HasPrefix(r.URL.Path, "/workspaces/12345/audit_log_events") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer 1/abcdef1234567890" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"gid":        "evt-1",
						"event_type": "user_invited",
						"created_at": "2024-01-01T10:00:00.123Z",
						"actor": map[string]interface{}{
							"gid":   "actor-1",
							"email": "admin@example.com",
						},
						"resource": map[string]interface{}{
							"gid":           "user-9",
							"resource_type": "user",
						},
					},
				},
				"next_page": map[string]interface{}{
					"offset": "cursor-2",
				},
			})
		case 1:
			call++
			if r.URL.Query().Get("offset") != "cursor-2" {
				t.Errorf("offset = %s", r.URL.Query().Get("offset"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"gid":        "evt-2",
						"event_type": "project_shared",
						"created_at": "2024-01-01T11:00:00Z",
						"actor": map[string]interface{}{
							"gid": "actor-2",
						},
						"resource": map[string]interface{}{
							"gid":           "proj-99",
							"resource_type": "project",
						},
					},
				},
				"next_page": map[string]interface{}{},
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
	if collected[0].EventType != "user_invited" || collected[0].TargetExternalID != "user-9" {
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
