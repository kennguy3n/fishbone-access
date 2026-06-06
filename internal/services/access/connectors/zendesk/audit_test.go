package zendesk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/audit_logs.json") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("auth header = %q", got)
		}
		if r.URL.Query().Get("page[after]") == "" && !strings.Contains(r.URL.RawQuery, "after_token") {
			// first page
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"next_page": "https://acme.zendesk.com/api/v2/audit_logs.json?page%5Bafter%5D=cur",
				"audit_logs": []map[string]interface{}{
					{
						"id":          int64(1001),
						"actor_id":    int64(7),
						"action":      "create",
						"source_id":   int64(42),
						"source_type": "User",
						"ip_address":  "203.0.113.1",
						"created_at":  "2024-01-01T10:00:00Z",
					},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"next_page": "",
			"audit_logs": []map[string]interface{}{
				{
					"id":          int64(1002),
					"actor_id":    int64(8),
					"action":      "update",
					"source_id":   int64(43),
					"source_type": "Ticket",
					"created_at":  "2024-01-01T11:00:00Z",
				},
			},
		})
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	c := New()
	c.urlOverride = serverURL
	c.httpClient = func() httpDoer { return server.Client() }

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
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].Action != "create" || collected[0].IPAddress != "203.0.113.1" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Action != "update" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
}

func TestFetchAccessAuditLogs_Forbidden_SoftSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}
