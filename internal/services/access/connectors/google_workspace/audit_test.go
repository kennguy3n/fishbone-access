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
