package msteams

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

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	var serverURL string
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auditLogs/signIns" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch call {
		case 0:
			filter := r.URL.Query().Get("$filter")
			if !strings.Contains(filter, "appDisplayName eq 'Microsoft Teams'") {
				t.Errorf("filter = %s", filter)
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":                "si-1",
						"createdDateTime":   "2024-01-01T10:00:00.123Z",
						"userId":            "user-1",
						"userPrincipalName": "alice@example.com",
						"appDisplayName":    "Microsoft Teams",
						"ipAddress":         "203.0.113.1",
						"clientAppUsed":     "Mobile Apps",
					},
				},
				"@odata.nextLink": fmt.Sprintf("%s/auditLogs/signIns?$skiptoken=p2", serverURL),
			})
		case 1:
			call++
			if r.URL.Query().Get("$skiptoken") != "p2" {
				t.Errorf("page2 skiptoken = %s", r.URL.Query().Get("$skiptoken"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":              "si-2",
						"createdDateTime": "2024-01-01T11:00:00Z",
						"userId":          "user-2",
						"appDisplayName":  "Microsoft Teams",
						"status": map[string]interface{}{
							"errorCode":     50158,
							"failureReason": "External challenge not satisfied.",
						},
					},
				},
			})
		default:
			t.Errorf("unexpected call %d", call)
		}
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL

	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{auditPartitionTeamsSignIns: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error {
			if partitionKey != auditPartitionTeamsSignIns {
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
	if collected[0].EventType != "signIn" || collected[0].ActorEmail != "alice@example.com" || collected[0].Outcome != "success" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[0].Timestamp.IsZero() {
		t.Errorf("entry 0 timestamp is zero")
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 outcome = %s", collected[1].Outcome)
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

// TestFetchAccessAuditLogs_SkipsUnparseableTimestamp is a regression test for
// mapTeamsSignIn previously emitting entries with a zero (0001-01-01) timestamp
// when createdDateTime was unparseable, diverging from every sibling connector
// which drops such records. Records with bad timestamps must be skipped, not
// surfaced to downstream consumers with a meaningless timestamp.
func TestFetchAccessAuditLogs_SkipsUnparseableTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"value": []map[string]interface{}{
				{
					"id":              "si-bad",
					"createdDateTime": "not-a-real-timestamp",
					"userId":          "user-bad",
					"appDisplayName":  "Microsoft Teams",
				},
				{
					"id":              "si-good",
					"createdDateTime": "2024-01-02T08:00:00Z",
					"userId":          "user-good",
					"appDisplayName":  "Microsoft Teams",
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{auditPartitionTeamsSignIns: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d, want 1 (zero-timestamp record must be dropped)", len(collected))
	}
	if collected[0].EventID != "si-good" {
		t.Errorf("EventID = %q, want si-good", collected[0].EventID)
	}
	for _, e := range collected {
		if e.Timestamp.IsZero() {
			t.Errorf("emitted entry %q has zero timestamp", e.EventID)
		}
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{auditPartitionTeamsSignIns: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{auditPartitionTeamsSignIns: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestFetchAccessAuditLogs_BoundedPagination(t *testing.T) {
	// A misbehaving endpoint that always returns @odata.nextLink must not loop
	// forever; the connector caps pagination at teamsAuditMaxPages.
	var serverURL string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(fmt.Sprintf(
			`{"value":[{"id":"s1","createdDateTime":"2024-01-01T10:00:00Z"}],"@odata.nextLink":%q}`,
			serverURL+"/auditLogs/signIns?next=1")))
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{}, func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls != teamsAuditMaxPages {
		t.Fatalf("calls = %d; want %d (bounded)", calls, teamsAuditMaxPages)
	}
}
