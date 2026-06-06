package hellosign

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: FetchAccessAuditLogs must invoke the handler once per
// provider page (per the access.AccessAuditor contract) instead of
// buffering every page into memory and calling the handler a single
// time at the end. Before the fix a full first page followed by a
// partial second page produced exactly one handler call; the fix
// produces one call per page so callers can persist nextSince as a
// monotonic cursor and resume mid-stream after a partial failure.
func TestHelloSignFetchAccessAuditLogs_HandlerCalledPerPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		var logs []map[string]interface{}
		switch page {
		case "1":
			// A full page (== per_page) signals "more pages follow".
			for i := 0; i < hellosignAuditPageSize; i++ {
				logs = append(logs, map[string]interface{}{
					"id":          fmt.Sprintf("p1-%d", i),
					"event_type":  "account.created",
					"action":      "create",
					"occurred_at": "2024-09-01T10:00:00Z",
					"account_id":  "acc-1",
				})
			}
		case "2":
			logs = append(logs, map[string]interface{}{
				"id":          "p2-0",
				"event_type":  "account.created",
				"action":      "create",
				"occurred_at": "2024-09-02T10:00:00Z",
				"account_id":  "acc-2",
			})
		default:
			t.Errorf("unexpected page request: %q", page)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": logs})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var handlerCalls int
	var total int
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			handlerCalls++
			total += len(batch)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if handlerCalls != 2 {
		t.Fatalf("handlerCalls = %d; want 2 (one per page)", handlerCalls)
	}
	if total != hellosignAuditPageSize+1 {
		t.Fatalf("total entries = %d; want %d", total, hellosignAuditPageSize+1)
	}
}
