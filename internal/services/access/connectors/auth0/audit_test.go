package auth0

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
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v2/logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch page {
		case 0:
			page++
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"log_id":      "log-1",
					"date":        "2024-01-01T10:00:00Z",
					"type":        "s",
					"description": "Successful login",
					"user_id":     "auth0|u1",
					"user_name":   "alice@example.com",
					"ip":          "203.0.113.1",
				},
			})
		case 1:
			if r.URL.Query().Get("from") != "log-1" {
				t.Errorf("from = %s", r.URL.Query().Get("from"))
			}
			page++
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"log_id":    "log-2",
					"date":      "2024-01-01T11:00:00Z",
					"type":      "f",
					"user_id":   "auth0|u2",
					"user_name": "bob@example.com",
				},
			})
		default:
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
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
	if collected[0].Outcome != "success" {
		t.Errorf("entry 0 outcome = %q", collected[0].Outcome)
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 outcome = %q", collected[1].Outcome)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
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
