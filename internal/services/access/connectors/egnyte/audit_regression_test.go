package egnyte

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: an audit event whose timestamp is empty or unparseable must be
// skipped rather than emitted with a zero Timestamp. A zero Timestamp becomes
// the watermark cursor and forces an infinite re-fetch of the same window on
// the next sync.
func TestMapEgnyteAuditEvent_SkipsZeroTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name string
		ts   string
	}{
		{"empty", ""},
		{"garbage", "not-a-timestamp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapEgnyteAuditEvent(&egnyteAuditEvent{ID: "evt-x", EventType: "FILE_UPLOAD", Timestamp: tc.ts})
			if got != nil {
				t.Fatalf("mapEgnyteAuditEvent(ts=%q) = %+v; want nil", tc.ts, got)
			}
		})
	}
	if got := mapEgnyteAuditEvent(&egnyteAuditEvent{ID: "evt-y", EventType: "FILE_UPLOAD", Timestamp: "2024-01-01T10:00:00Z"}); got == nil {
		t.Fatal("valid event unexpectedly skipped")
	}
}

// Regression: a provider that keeps returning full pages must not spin the
// offset loop forever. The sweep is bounded by egnyteAuditMaxPages. The mock
// returns a hard error on the (cap+1)-th request so that, without the cap, the
// test fails loudly instead of hanging.
func TestFetchAccessAuditLogs_PageCap(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if int(atomic.AddInt32(&calls, 1)) > egnyteAuditMaxPages {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rows := make([]map[string]interface{}, 0, 100)
		for i := 0; i < 100; i++ {
			rows = append(rows, map[string]interface{}{
				"id":        "evt",
				"eventType": "noop",
				"timestamp": "2024-01-01T10:00:00Z",
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": rows})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != int32(egnyteAuditMaxPages) {
		t.Fatalf("requests = %d; want %d (loop must stop at the page cap)", got, egnyteAuditMaxPages)
	}
}
