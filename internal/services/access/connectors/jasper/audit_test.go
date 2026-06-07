package jasper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestJasperFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit-logs" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer token")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{{
				"id":          "jp-1",
				"event_type":  "user.added",
				"action":      "add",
				"occurred_at": "2024-09-01T10:00:00Z",
				"actor_id":    "u-7",
				"actor_email": "ops@example.com",
				"target_id":   "u-99",
				"ip_address":  "10.0.0.10",
			}},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].TargetExternalID != "u-99" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestJasperFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestJasperFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}

// TestJasperFetchAccessAuditLogs_EmitsPerPage proves the connector invokes the
// handler once per provider page (AccessAuditor contract) instead of buffering
// every page into a single batch. See the ironclad sibling for rationale.
func TestJasperFetchAccessAuditLogs_EmitsPerPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			rows := make([]map[string]interface{}, jasperAuditPageSize)
			for i := range rows {
				rows[i] = map[string]interface{}{
					"id":          fmt.Sprintf("evt-%d", i),
					"event_type":  "user.login",
					"occurred_at": time.Date(2024, 9, 1, 0, 0, i, 0, time.UTC).Format(time.RFC3339),
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": rows})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{{
			"id":          "evt-last",
			"event_type":  "user.login",
			"occurred_at": "2024-09-02T10:00:00Z",
		}}})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var calls, total int
	var last time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			calls++
			total += len(batch)
			if n.Before(last) {
				t.Errorf("nextSince regressed: %s < %s", n, last)
			}
			last = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls < 2 {
		t.Fatalf("handler called %d time(s); want one call per page (>=2)", calls)
	}
	if total != jasperAuditPageSize+1 {
		t.Fatalf("total entries = %d; want %d", total, jasperAuditPageSize+1)
	}
	if !last.Equal(time.Date(2024, 9, 2, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("final nextSince = %s; want 2024-09-02T10:00:00Z", last)
	}
}
