package cloudflare

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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/accounts/acct-123/audit_logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result_info": map[string]interface{}{
					"page": 1, "per_page": 100, "total_pages": 2,
				},
				"result": []map[string]interface{}{
					{
						"id":   "ev-1",
						"when": "2024-01-01T10:00:00Z",
						"action": map[string]interface{}{
							"type":   "user.login",
							"result": true,
						},
						"actor": map[string]interface{}{
							"id":    "u-1",
							"email": "alice@example.com",
							"ip":    "203.0.113.1",
						},
						"user_agent": "ua-1",
						"resource":   map[string]interface{}{"id": "zone-1", "type": "zone"},
					},
				},
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"result_info": map[string]interface{}{
					"page": 2, "per_page": 100, "total_pages": 2,
				},
				"result": []map[string]interface{}{
					{
						"id":   "ev-2",
						"when": "2024-01-01T11:00:00Z",
						"action": map[string]interface{}{
							"type":   "policy.update",
							"result": false,
						},
						"actor": map[string]interface{}{
							"id":    "u-2",
							"email": "bob@example.com",
						},
					},
				},
			})
		default:
			t.Errorf("unexpected page %q", page)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
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
	if collected[0].Outcome != "success" || collected[0].IPAddress != "203.0.113.1" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" || collected[1].EventType != "policy.update" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

func TestFetchAccessAuditLogs_ZeroSinceOmitsFilter(t *testing.T) {
	var observed string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"result":  []map[string]interface{}{},
			"result_info": map[string]interface{}{
				"page": 1, "per_page": 100, "total_pages": 1,
			},
		})
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if strings.Contains(observed, "since=") {
		t.Errorf("zero-since first backfill must omit `since`; got %q", observed)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000}]}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}
