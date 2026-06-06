package dropbox

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
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/2/team_log/get_events":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"has_more": true,
				"cursor":   "cur-2",
				"events": []map[string]interface{}{
					{
						"timestamp":  "2024-01-01T10:00:00Z",
						"event_type": map[string]interface{}{".tag": "member_change_status", "description": "Member status changed"},
						"actor":      map[string]interface{}{"user": map[string]interface{}{"email": "alice@example.com", "account_id": "u-1"}},
					},
				},
			})
		case "/2/team_log/get_events/continue":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"has_more": false,
				"cursor":   "",
				"events": []map[string]interface{}{
					{
						"timestamp":  "2024-01-01T11:00:00Z",
						"event_type": map[string]interface{}{".tag": "shared_folder_change_link_access", "description": "Shared link access changed"},
						"actor":      map[string]interface{}{"user": map[string]interface{}{"email": "bob@example.com"}},
					},
				},
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
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
	if collected[0].EventType != "member_change_status" || collected[0].ActorEmail != "alice@example.com" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
}

func TestFetchAccessAuditLogs_Forbidden_SoftSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error_summary":"team_log not available"}`))
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
