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

func TestFetchAccessAuditLogs_SoftSkipStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
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

// An audit row with an empty or unparseable dateCreated must be dropped
// rather than ingested with a zero Timestamp (which would corrupt cursor
// tracking). Matches every other audit mapper in this batch.
func TestMapSentryAuditLog_DropsZeroTimestamp(t *testing.T) {
	for _, in := range []string{"", "not-a-date", "2024/01/01 10:00:00"} {
		if got := mapSentryAuditLog(&sentryAuditLog{ID: "x", Event: "member.add", DateCreated: in}); got != nil {
			t.Errorf("dateCreated=%q: got %+v; want nil", in, got)
		}
	}
	if got := mapSentryAuditLog(&sentryAuditLog{ID: "y", Event: "member.add", DateCreated: "2024-01-01T10:00:00Z"}); got == nil {
		t.Fatal("valid timestamp: got nil, want entry")
	}
}

// TestFetchAccessAuditLogs_RejectsOffHostPagination pins the assertSameHost
// guard on the audit pagination loop: a rel="next" Link header pointing off
// the API host must be refused rather than followed, since the loop attaches
// the bearer token via newRequest. Mirrors the SyncIdentities guard and the
// GitHub audit guard. The off-host server must never be contacted.
func TestFetchAccessAuditLogs_RejectsOffHostPagination(t *testing.T) {
	contacted := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("bearer token leaked off-host: %q", got)
		}
		_, _ = w.Write([]byte(`{"rows":[]}`))
	}))
	t.Cleanup(evil.Close)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// First page is empty but points "next" off-host.
		w.Header().Set("Link", `<`+evil.URL+`/api/0/organizations/acme/audit-logs/?cursor=0:100:0>; rel="next"; results="true"`)
		_, _ = w.Write([]byte(`{"rows":[]}`))
	}))
	t.Cleanup(api.Close)

	c := New()
	c.urlOverride = api.URL
	c.httpClient = func() httpDoer { return api.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected error for off-host audit pagination, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected host") {
		t.Fatalf("error = %v; want host-mismatch refusal", err)
	}
	if contacted {
		t.Fatal("off-host server was contacted with the bearer token")
	}
}
