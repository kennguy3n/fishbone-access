package snyk

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
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/rest/orgs/abc-org/audit_logs/search") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "token ") {
			t.Errorf("auth header = %q", got)
		}
		calls++
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"links": map[string]interface{}{"next": "/rest/orgs/abc-org/audit_logs/search?version=2024-08-25&page=2"},
				"data": []map[string]interface{}{
					{
						"id":   "ev-1",
						"type": "audit_log",
						"attributes": map[string]interface{}{
							"created_at": "2024-01-01T10:00:00Z",
							"event":      "user.org.invite",
							"user_id":    "u-1",
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
					"type": "audit_log",
					"attributes": map[string]interface{}{
						"created_at": "2024-01-01T11:00:00Z",
						"event":      "project.create",
						"user_id":    "u-2",
						"project_id": "p-100",
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
	if collected[0].EventType != "user.org.invite" || collected[0].ActorExternalID != "u-1" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].TargetExternalID != "p-100" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
}

func TestFetchAccessAuditLogs_Forbidden_SoftSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
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
