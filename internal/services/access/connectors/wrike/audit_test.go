package wrike

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

func wrikeAuditConfig() map[string]interface{}  { return map[string]interface{}{} }
func wrikeAuditSecrets() map[string]interface{} { return map[string]interface{}{"token": "tok"} }

func TestWrikeFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/audit_log" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"kind": "audit_log",
			"data": []map[string]interface{}{{
				"id":         "evt-1",
				"operation":  "user.login",
				"eventDate":  "2024-09-01T10:00:00Z",
				"userId":     "u-1",
				"userEmail":  "admin@example.com",
				"objectType": "user",
				"objectId":   "u-1",
				"ipAddress":  "10.0.0.1",
			}},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), wrikeAuditConfig(), wrikeAuditSecrets(),
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

// TestWrikeFetchAccessAuditLogs_SendsServerSideDateFilter guards against
// paging the entire account audit history on every tick. When a watermark
// (since) is present, the connector must push it to the server via Wrike's
// `eventDate` range filter on the first request so the API only returns
// events newer than the cursor, rather than relying solely on client-side
// discarding. The page token carries the filter on subsequent pages, so the
// explicit filter should appear only on the first (no-token) request.
func TestWrikeFetchAccessAuditLogs_SendsServerSideDateFilter(t *testing.T) {
	since := time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)
	var gotEventDate string
	var sawFilter bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("eventDate"); v != "" {
			gotEventDate = v
			sawFilter = true
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"kind": "audit_log",
			"data": []map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), wrikeAuditConfig(), wrikeAuditSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: since},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if !sawFilter {
		t.Fatal("server never received an eventDate filter; connector paged without a server-side watermark")
	}
	// The filter must be a range object pinned to the watermark start.
	var parsed struct {
		Start string `json:"start"`
	}
	if err := json.Unmarshal([]byte(gotEventDate), &parsed); err != nil {
		t.Fatalf("eventDate=%q is not a JSON range object: %v", gotEventDate, err)
	}
	if parsed.Start != "2024-09-01T10:00:00Z" {
		t.Errorf("eventDate.start = %q, want %q", parsed.Start, "2024-09-01T10:00:00Z")
	}
}

func TestWrikeFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), wrikeAuditConfig(), wrikeAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestWrikeFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), wrikeAuditConfig(), wrikeAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}
