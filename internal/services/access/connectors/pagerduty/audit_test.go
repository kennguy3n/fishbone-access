package pagerduty

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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/audit/records") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Token token=") {
			t.Errorf("auth header = %q", got)
		}
		if r.URL.Query().Get("cursor") == "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"more":        true,
				"next_cursor": "cur-2",
				"records": []map[string]interface{}{
					{
						"id":             "rec-1",
						"execution_time": "2024-01-01T10:00:00Z",
						"action":         "create",
						"actors": []map[string]interface{}{
							{"id": "u-1", "type": "user_reference", "email": "alice@example.com"},
						},
						"root_resource": map[string]interface{}{"id": "ser-1", "type": "service_reference"},
					},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"more":        false,
			"next_cursor": "",
			"records": []map[string]interface{}{
				{
					"id":             "rec-2",
					"execution_time": "2024-01-01T11:00:00Z",
					"action":         "update",
					"actors":         []map[string]interface{}{{"id": "u-2", "email": "bob@example.com"}},
				},
			},
		})
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
	if collected[0].Action != "create" || collected[0].ActorEmail != "alice@example.com" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Action != "update" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
}

func TestFetchAccessAuditLogs_PlanGatedSoftSkip(t *testing.T) {
	// The Audit Records API is gated behind the PagerDuty Business /
	// Digital Operations plan; tenants without it receive 401/403/404.
	// Those must surface as access.ErrAuditNotAvailable (a soft-skip) so
	// the pipeline treats them as plan-gated rather than actionable
	// failures, matching every other auditor in this package.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		c := New()
		c.urlOverride = server.URL
		c.httpClient = func() httpDoer { return server.Client() }
		err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
			map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
			func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
		if !errors.Is(err, access.ErrAuditNotAvailable) {
			t.Errorf("status %d: err = %v; want ErrAuditNotAvailable", status, err)
		}
		server.Close()
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
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
