package teamwork

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

func teamworkAuditConfig() map[string]interface{} {
	return map[string]interface{}{"subdomain": "acme"}
}
func teamworkAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "key-1"}
}

func TestTeamworkFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/projects/api/v3/audit.json" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"audit_trail": []map[string]interface{}{{
				"id":         int64(1001),
				"event":      "user.login",
				"eventDate":  "2024-09-01T10:00:00Z",
				"userId":     int64(7),
				"userEmail":  "admin@example.com",
				"objectType": "user",
				"objectId":   int64(7),
				"ipAddress":  "10.0.0.1",
			}},
			"meta": map[string]int{"page": 1, "total": 1},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), teamworkAuditConfig(), teamworkAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].ActorEmail != "admin@example.com" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

// TestTeamworkFetchAccessAuditLogs_DoesNotStopOnOlderEvent verifies the audit
// sweep does not terminate early when it encounters events older than the
// watermark. The endpoint has no server-side time filter and does not
// guarantee newest-first ordering; if the provider returns events oldest-first,
// page 1 (all older than the cursor) must not short-circuit the loop and cause
// the newer events on page 2 to be silently dropped.
func TestTeamworkFetchAccessAuditLogs_DoesNotStopOnOlderEvent(t *testing.T) {
	since := time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			// A full page of events all OLDER than the cursor (ascending order).
			items := make([]map[string]interface{}, 0, teamworkAuditPageSize)
			for i := 0; i < teamworkAuditPageSize; i++ {
				items = append(items, map[string]interface{}{
					"id":        int64(1000 + i),
					"event":     "user.login",
					"eventDate": "2024-08-01T10:00:00Z",
					"userId":    int64(7),
					"userEmail": "old@example.com",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"audit_trail": items,
				"meta":        map[string]int{"page": 1, "total": teamworkAuditPageSize + 1},
			})
		case "2":
			// A newer event sitting on a later page.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"audit_trail": []map[string]interface{}{{
					"id":        int64(2001),
					"event":     "user.login",
					"eventDate": "2024-09-15T10:00:00Z",
					"userId":    int64(9),
					"userEmail": "new@example.com",
				}},
				"meta": map[string]int{"page": 2, "total": teamworkAuditPageSize + 1},
			})
		default:
			t.Fatalf("unexpected page %q", page)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), teamworkAuditConfig(), teamworkAuditSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: since},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 pages fetched, got %d (loop stopped early on older events)", calls)
	}
	if len(collected) != 1 || collected[0].ActorEmail != "new@example.com" {
		t.Fatalf("collected = %+v; want the single newer event from page 2", collected)
	}
}

func TestTeamworkFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), teamworkAuditConfig(), teamworkAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestTeamworkFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), teamworkAuditConfig(), teamworkAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
