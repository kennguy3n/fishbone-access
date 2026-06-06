package insightly

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

func TestInsightlyFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3.1/Events" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
			"EVENT_ID":         int64(2001),
			"TITLE":            "Quarterly review",
			"EVENT_TYPE":       "Meeting",
			"START_DATE_UTC":   "2024-09-01 10:00:00",
			"DATE_UPDATED_UTC": "2024-09-01 11:00:00",
			"OWNER_USER_ID":    int64(33),
		}})
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
	if len(collected) != 1 || collected[0].EventType != "Meeting" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestInsightlyFetchAccessAuditLogs_NotAvailable(t *testing.T) {
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

func TestInsightlyFetchAccessAuditLogs_TransientFailure(t *testing.T) {
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

// TestInsightlyFetchAccessAuditLogs_EmitsPerPage proves the connector invokes
// the handler once per provider page (AccessAuditor contract) instead of
// buffering every page into a single batch. A full first page (skip=0) forces a
// second request (skip=100); the handler must be called at least twice with a
// monotonically non-decreasing nextSince. Fails against the buffer-then-emit
// implementation, which calls the handler exactly once.
func TestInsightlyFetchAccessAuditLogs_EmitsPerPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("skip") == "0" {
			rows := make([]map[string]interface{}, insightlyAuditPageSize)
			for i := range rows {
				rows[i] = map[string]interface{}{
					"EVENT_ID":         int64(1000 + i),
					"EVENT_TYPE":       "Meeting",
					"DATE_UPDATED_UTC": time.Date(2024, 9, 1, 10, 0, i, 0, time.UTC).Format("2006-01-02 15:04:05"),
				}
			}
			_ = json.NewEncoder(w).Encode(rows)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
			"EVENT_ID":         int64(9999),
			"EVENT_TYPE":       "Meeting",
			"DATE_UPDATED_UTC": "2024-09-02 10:00:00",
		}})
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
	if total != insightlyAuditPageSize+1 {
		t.Fatalf("total entries = %d; want %d", total, insightlyAuditPageSize+1)
	}
	if !last.Equal(time.Date(2024, 9, 2, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("final nextSince = %s; want 2024-09-02T10:00:00Z", last)
	}
}
