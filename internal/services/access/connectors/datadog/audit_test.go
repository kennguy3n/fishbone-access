package datadog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	var nextURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("DD-API-KEY"); got == "" {
			t.Errorf("missing DD-API-KEY")
		}
		if got := r.Header.Get("DD-APPLICATION-KEY"); got == "" {
			t.Errorf("missing DD-APPLICATION-KEY")
		}
		if r.URL.Query().Get("page[cursor]") == "" {
			nextURL = "https://api.datadoghq.com/api/v2/audit/events?page%5Bcursor%5D=cur-2"
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"links": map[string]interface{}{"next": nextURL},
				"data": []map[string]interface{}{
					{
						"id":   "ev-1",
						"type": "audit",
						"attributes": map[string]interface{}{
							"timestamp": "2024-01-01T10:00:00Z",
							"service":   "audit-trail",
							"attributes": map[string]interface{}{
								"evt.name":  "user.login",
								"usr.email": "alice@example.com",
								"usr.id":    "u-1",
							},
						},
					},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"links": map[string]interface{}{},
			"data": []map[string]interface{}{
				{
					"id":   "ev-2",
					"type": "audit",
					"attributes": map[string]interface{}{
						"timestamp": "2024-01-01T11:00:00Z",
						"attributes": map[string]interface{}{
							"evt.name":  "team.update",
							"usr.email": "bob@example.com",
						},
					},
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
	if collected[0].EventType != "user.login" || collected[0].ActorEmail != "alice@example.com" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].EventType != "team.update" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
}

func TestFetchAccessAuditLogs_Forbidden_SoftSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["Forbidden"]}`))
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

// TestFetchAccessAuditLogs_SoftSkipStatuses pins the full audit
// not-available set (401/403/404 per docs/architecture.md §2). Datadog
// previously only soft-skipped 403, so an expired key (401) or an
// absent endpoint (404) surfaced as a hard error and broke the pipeline.
func TestFetchAccessAuditLogs_SoftSkipStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"errors":["nope"]}`))
			}))
			t.Cleanup(server.Close)
			c := New()
			c.urlOverride = server.URL
			c.httpClient = func() httpDoer { return server.Client() }
			err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
				map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
				func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
			if err != access.ErrAuditNotAvailable {
				t.Fatalf("status %d: err = %v; want ErrAuditNotAvailable", status, err)
			}
		})
	}
}

// TestFetchAccessAuditLogs_MaxPageCap proves the cursor loop is bounded.
// The server returns a perpetual links.next (circular cursor); without
// the datadogAuditMaxPages cap the loop would never terminate. The
// escape hatch at +50 requests only fires if the cap failed, so the
// assertion that exactly datadogAuditMaxPages requests were made is what
// guards the fix.
func TestFetchAccessAuditLogs_MaxPageCap(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		next := ""
		if hits < datadogAuditMaxPages+50 {
			next = "https://api.datadoghq.com/api/v2/audit/events?page%5Bcursor%5D=loop"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"links": map[string]interface{}{"next": next},
			"data":  []map[string]interface{}{},
		})
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if hits != datadogAuditMaxPages {
		t.Fatalf("made %d requests, want exactly %d (cursor loop must be capped)", hits, datadogAuditMaxPages)
	}
}

// TestFetchAccessAuditLogs_SkipsUnparseableTimestamp verifies the mapper
// drops an event whose timestamp is present but unparseable instead of
// emitting a zero-value (year 0001) entry. The partition is zero (a first
// run), so a zero-timestamp entry would otherwise slip into the batch.
func TestFetchAccessAuditLogs_SkipsUnparseableTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"links": map[string]interface{}{},
			"data": []map[string]interface{}{
				{"id": "ev-bad", "type": "audit", "attributes": map[string]interface{}{
					"timestamp": "not-a-timestamp",
					"attributes": map[string]interface{}{"evt.name": "user.login", "usr.email": "bad@example.com"},
				}},
				{"id": "ev-ok", "type": "audit", "attributes": map[string]interface{}{
					"timestamp": "2024-01-01T10:00:00Z",
					"attributes": map[string]interface{}{"evt.name": "user.login", "usr.email": "ok@example.com"},
				}},
			},
		})
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("collected %d entries, want 1 (unparseable timestamp must be dropped)", len(collected))
	}
	if collected[0].Timestamp.IsZero() {
		t.Fatalf("emitted entry has zero timestamp: %+v", collected[0])
	}
}
