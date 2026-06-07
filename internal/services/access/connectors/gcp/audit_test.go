package gcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/entries:list" {
			t.Errorf("path = %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var got map[string]interface{}
		_ = json.Unmarshal(body, &got)
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entries": []map[string]interface{}{
					{
						"insertId":  "e1",
						"logName":   "projects/uney-prod/logs/cloudaudit.googleapis.com%2Factivity",
						"timestamp": "2024-01-01T10:00:00Z",
						"protoPayload": map[string]interface{}{
							"serviceName":  "iam.googleapis.com",
							"methodName":   "google.iam.admin.v1.SetIamPolicy",
							"resourceName": "projects/uney-prod",
							"authenticationInfo": map[string]interface{}{
								"principalEmail": "alice@corp.example",
							},
							"requestMetadata": map[string]interface{}{
								"callerIp": "203.0.113.1",
							},
						},
					},
				},
				"nextPageToken": "tk2",
			})
		case 1:
			if got["pageToken"] != "tk2" {
				t.Errorf("pageToken = %v", got["pageToken"])
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entries": []map[string]interface{}{
					{
						"insertId":  "e2",
						"timestamp": "2024-01-01T11:00:00Z",
						"protoPayload": map[string]interface{}{
							"serviceName":  "iam.googleapis.com",
							"methodName":   "google.iam.admin.v1.DeleteRole",
							"resourceName": "projects/uney-prod/roles/X",
							"authenticationInfo": map[string]interface{}{
								"principalEmail": "bob@corp.example",
							},
							"status": map[string]interface{}{"code": 7, "message": "permission denied"},
						},
					},
				},
			})
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

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
	if collected[0].Outcome != "success" || collected[0].ActorEmail != "alice@corp.example" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 outcome = %q", collected[1].Outcome)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMapGCPLogEntry_ParsesNanoTimestampAndSkipsZero(t *testing.T) {
	// Cloud Logging emits RFC3339 with nanosecond precision; it must parse
	// to a non-zero UTC instant so the sync cursor advances each run.
	entry := mapGCPLogEntry(&gcpLogEntry{InsertID: "e1", Timestamp: "2024-01-15T10:30:45.123456789Z"})
	if entry == nil {
		t.Fatal("entry = nil; want mapped entry")
	}
	if entry.Timestamp.IsZero() {
		t.Error("timestamp is zero; RFC3339Nano was not parsed")
	}
	if entry.Timestamp.Location() != time.UTC {
		t.Errorf("location = %v; want UTC", entry.Timestamp.Location())
	}
	// An unparseable timestamp must skip the entry rather than emit a
	// zero-time record that would stall batchMax / the cursor.
	if got := mapGCPLogEntry(&gcpLogEntry{InsertID: "e2", Timestamp: "not-a-time"}); got != nil {
		t.Errorf("entry with bad timestamp = %+v; want nil", got)
	}
}
