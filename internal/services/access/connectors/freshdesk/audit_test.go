package freshdesk

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
		if !strings.HasPrefix(r.URL.Path, "/api/v2/audit_log") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("auth missing")
		}
		switch call {
		case 0:
			call++
			if r.URL.Query().Get("page") != "1" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			rows := make([]map[string]interface{}, 0, 100)
			rows = append(rows, map[string]interface{}{
				"id":         1001,
				"action":     "agent_invited",
				"created_at": "2024-01-01T10:00:00Z",
				"user_id":    42,
				"user_email": "admin@example.com",
				"object":     "agent",
				"object_id":  999,
			})
			for i := 1; i < 100; i++ {
				rows = append(rows, map[string]interface{}{
					"id":         9000 + i,
					"action":     "noop",
					"created_at": "2024-01-01T10:30:00Z",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": rows})
		case 1:
			call++
			if r.URL.Query().Get("page") != "2" {
				t.Errorf("page = %s", r.URL.Query().Get("page"))
			}
			// Last page returns < perPage rows.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"audit_logs": []map[string]interface{}{
					{
						"id":         1002,
						"action":     "role_updated",
						"created_at": "2024-01-01T11:00:00Z",
						"user_id":    43,
						"object":     "role",
						"object_id":  77,
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
	if collected[0].EventType != "agent_invited" || collected[0].TargetExternalID != "999" {
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
