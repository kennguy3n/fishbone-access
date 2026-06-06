package aws

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != cloudTrailTarget {
			t.Errorf("X-Amz-Target = %s", r.Header.Get("X-Amz-Target"))
		}
		body, _ := io.ReadAll(r.Body)
		var got map[string]interface{}
		_ = json.Unmarshal(body, &got)
		switch call {
		case 0:
			if _, ok := got["StartTime"]; !ok {
				t.Errorf("missing StartTime in body: %v", got)
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Events": []map[string]interface{}{
					{
						"EventId":     "evt-1",
						"EventName":   "ConsoleLogin",
						"EventTime":   1704110400,
						"Username":    "alice",
						"EventSource": "signin.amazonaws.com",
					},
				},
				"NextToken": "n1",
			})
		case 1:
			if got["NextToken"] != "n1" {
				t.Errorf("NextToken = %v", got["NextToken"])
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Events": []map[string]interface{}{
					{
						"EventId":     "evt-2",
						"EventName":   "AssumeRole",
						"EventTime":   1704114000,
						"Username":    "bob",
						"EventSource": "sts.amazonaws.com",
						"Resources": []map[string]interface{}{
							{"ResourceType": "AWS::IAM::Role", "ResourceName": "arn:aws:iam::1:role/A"},
						},
					},
				},
			})
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }

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
	if collected[0].Action != "ConsoleLogin" || collected[0].ActorEmail != "alice" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].TargetExternalID == "" || !strings.Contains(collected[1].TargetExternalID, "role/A") {
		t.Errorf("entry 1 target = %q", collected[1].TargetExternalID)
	}
}

func TestFetchAccessAuditLogs_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error")
	}
}
