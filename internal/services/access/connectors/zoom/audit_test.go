package zoom

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
		if !strings.HasPrefix(r.URL.Path, "/report/activities") {
			t.Errorf("path = %s", r.URL.Path)
		}
		calls++
		if r.URL.Query().Get("next_page_token") == "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"next_page_token": "tok-2",
				"activity_logs": []map[string]interface{}{
					{
						"time":       "2024-01-01T10:00:00Z",
						"email":      "alice@example.com",
						"user_name":  "Alice",
						"type":       "Sign in",
						"ip_address": "203.0.113.1",
						"user_agent": "ua-1",
					},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"next_page_token": "",
			"activity_logs": []map[string]interface{}{
				{
					"time":        "2024-01-01T11:00:00Z",
					"email":       "bob@example.com",
					"type":        "Sign out",
					"client_type": "Web",
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "tok", nil
	}

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
	if collected[0].ActorEmail != "alice@example.com" || collected[0].IPAddress != "203.0.113.1" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].EventType != "Sign out" {
		t.Errorf("entry 1 type = %q", collected[1].EventType)
	}
	if calls != 2 {
		t.Errorf("calls = %d", calls)
	}
}

func TestMapZoomActivity_TimestampParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want time.Time
	}{
		{"rfc3339", "2024-01-01T10:00:00Z", time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)},
		{"rfc3339_nano", "2024-01-01T10:00:00.123456789Z", time.Date(2024, 1, 1, 10, 0, 0, 123456789, time.UTC)},
		{"rfc3339_millis", "2024-01-01T10:00:00.123Z", time.Date(2024, 1, 1, 10, 0, 0, 123000000, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapZoomActivity(&zoomActivity{Time: tc.in, Email: "u@x", Type: "t"})
			if got == nil {
				t.Fatalf("nil entry")
			}
			if !got.Timestamp.Equal(tc.want) {
				t.Errorf("timestamp = %v; want %v", got.Timestamp, tc.want)
			}
		})
	}
}

// TestMapZoomActivity_DropsUnparseableTime is a regression test: an activity
// with a non-empty but unparseable `time` must be dropped (nil), not emitted
// with a zero Timestamp. A zero-valued Timestamp pollutes the audit stream
// and prevents the watermark cursor from advancing.
func TestMapZoomActivity_DropsUnparseableTime(t *testing.T) {
	for _, bad := range []string{
		"2024-01-01 10:00:00", // space instead of 'T', not RFC3339
		"01/02/2024 10:00:00", // US-style, unparseable
		"not-a-timestamp",     // garbage
	} {
		if got := mapZoomActivity(&zoomActivity{Time: bad, Email: "u@x", Type: "Sign in"}); got != nil {
			t.Errorf("time %q: got entry %+v; want nil (dropped)", bad, got)
		}
	}
}

func TestFetchAccessAuditLogs_Unauthorized_SoftSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":300,"message":"plan does not allow reports"}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) {
		return "tok", nil
	}
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != access.ErrAuditNotAvailable {
		t.Fatalf("err = %v; want ErrAuditNotAvailable", err)
	}
}
