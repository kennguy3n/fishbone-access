package google_workspace

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
		if !strings.Contains(r.URL.Path, "/activity/users/all/applications/login") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch r.URL.Query().Get("pageToken") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id": map[string]interface{}{
							"time":            "2024-01-01T10:00:00Z",
							"uniqueQualifier": "act-1",
							"applicationName": "login",
						},
						"actor":     map[string]interface{}{"email": "alice@example.com", "profileId": "u-1"},
						"ipAddress": "203.0.113.1",
						"events": []map[string]interface{}{
							{"type": "login", "name": "login_success", "parameters": []map[string]interface{}{}},
						},
					},
				},
				"nextPageToken": "p2",
			})
		case "p2":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id": map[string]interface{}{
							"time":            "2024-01-01T11:00:00Z",
							"uniqueQualifier": "act-2",
							"applicationName": "login",
						},
						"actor": map[string]interface{}{"email": "bob@example.com", "profileId": "u-2"},
						"events": []map[string]interface{}{
							{
								"type": "login",
								"name": "login_failure",
								"parameters": []map[string]interface{}{
									{"name": "login_failure_type", "value": "login_failure_invalid_password"},
								},
							},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected pageToken %s", r.URL.Query().Get("pageToken"))
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}

	var collected []*access.AuditLogEntry
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(t),
		map[string]time.Time{access.DefaultAuditPartition: since},
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
	if collected[0].EventID != "act-1" || collected[0].Outcome != "success" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 outcome = %q", collected[1].Outcome)
	}
}

// TestMapReportsActivity_DropsUnparseableTimestamp pins the
// zero-timestamp guard: an activity whose id.time cannot be parsed must
// be dropped (nil) rather than emitted with a 0001-01-01 timestamp, which
// would never advance the max-based watermark cursor and would re-fetch
// the same window every sync cycle. Matches every other audit mapper in
// this batch. A well-formed timestamp must still map through.
func TestMapReportsActivity_DropsUnparseableTimestamp(t *testing.T) {
	bad := &reportsActivity{}
	bad.ID.UniqueQualifier = "act-bad"
	bad.ID.ApplicationName = "login"
	bad.ID.Time = "not-a-timestamp"
	if got := mapReportsActivity(bad); got != nil {
		t.Fatalf("expected nil for unparseable timestamp, got %+v", got)
	}

	empty := &reportsActivity{}
	empty.ID.UniqueQualifier = "act-empty"
	empty.ID.Time = ""
	if got := mapReportsActivity(empty); got != nil {
		t.Fatalf("expected nil for empty timestamp, got %+v", got)
	}

	good := &reportsActivity{}
	good.ID.UniqueQualifier = "act-ok"
	good.ID.ApplicationName = "login"
	good.ID.Time = "2024-01-01T10:00:00Z"
	got := mapReportsActivity(good)
	if got == nil {
		t.Fatal("expected entry for valid timestamp, got nil")
	}
	if got.Timestamp.IsZero() || !got.Timestamp.Equal(time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("Timestamp = %v; want 2024-01-01T10:00:00Z", got.Timestamp)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(t),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error on 403")
	}
}

// TestFetchAccessAuditLogs_BoundedPages pins the gwAuditMaxPages cap: a Reports
// API that always returns a non-empty nextPageToken (a server-side cursor bug)
// must not spin the pagination loop forever. The sweep stops at the cap and
// returns nil (remaining pages deferred to the next sync, since the watermark
// advanced per page). Mirrors the caps on sibling audit connectors.
func TestFetchAccessAuditLogs_BoundedPages(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		// Always hand back another page token => unbounded without the cap.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"items": []map[string]interface{}{{
				"id":    map[string]interface{}{"time": "2024-01-01T10:00:00Z", "uniqueQualifier": "act", "applicationName": "login"},
				"actor": map[string]interface{}{"email": "alice@example.com", "profileId": "u-1"},
				"events": []map[string]interface{}{
					{"type": "login", "name": "login_success", "parameters": []map[string]interface{}{}},
				},
			}},
			"nextPageToken": "always-more",
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(t),
		map[string]time.Time{access.DefaultAuditPartition: since},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if requests != gwAuditMaxPages {
		t.Fatalf("requests = %d, want %d (loop must stop at the page cap)", requests, gwAuditMaxPages)
	}
}
