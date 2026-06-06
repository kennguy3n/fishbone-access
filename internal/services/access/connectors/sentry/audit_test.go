package sentry

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
		if !strings.HasPrefix(r.URL.Path, "/api/0/organizations/acme/audit-logs/") {
			t.Errorf("path = %s", r.URL.Path)
		}
		calls++
		switch calls {
		case 1:
			w.Header().Set("Link", `<https://sentry.io/api/0/organizations/acme/audit-logs/?cursor=0:100:0>; rel="next"; results="true"; cursor="0:100:0"`)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"rows": []map[string]interface{}{
					{
						"id":          "1",
						"event":       "member.invite",
						"dateCreated": "2024-01-01T10:00:00Z",
						"actor":       map[string]interface{}{"id": "u-1", "email": "alice@example.com"},
						"ipAddress":   "203.0.113.1",
					},
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"rows": []map[string]interface{}{
					{
						"id":          "2",
						"event":       "org.edit",
						"dateCreated": "2024-01-01T11:00:00Z",
						"actor":       map[string]interface{}{"id": "u-2", "email": "bob@example.com"},
					},
				},
			})
		}
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
	if collected[0].EventType != "member.invite" || collected[0].ActorEmail != "alice@example.com" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].EventType != "org.edit" {
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
