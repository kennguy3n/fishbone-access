package dropbox

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

// Regression: a team-log event whose timestamp is empty or unparseable must be
// skipped rather than emitted with a zero Timestamp. A zero Timestamp becomes
// the watermark cursor and forces an infinite re-fetch of the same window on
// the next sync.
func TestMapDropboxEvent_SkipsZeroTimestamp(t *testing.T) {
	bad := &dropboxEvent{Timestamp: "not-a-timestamp"}
	bad.EventType.Tag = "file_add"
	if got := mapDropboxEvent(bad); got != nil {
		t.Fatalf("mapDropboxEvent(bad ts) = %+v; want nil", got)
	}

	empty := &dropboxEvent{Timestamp: ""}
	empty.EventType.Tag = "file_add"
	if got := mapDropboxEvent(empty); got != nil {
		t.Fatalf("mapDropboxEvent(empty ts) = %+v; want nil", got)
	}

	good := &dropboxEvent{Timestamp: "2024-01-01T10:00:00Z"}
	good.EventType.Tag = "file_add"
	if got := mapDropboxEvent(good); got == nil {
		t.Fatal("valid event unexpectedly skipped")
	}
}

// Regression: a provider that keeps returning has_more=true must not spin the
// pagination loop forever. The sweep is bounded by dropboxAuditMaxPages. The
// mock returns a hard error on the (cap+1)-th request so that, without the cap,
// the test fails loudly instead of hanging.
func TestFetchAccessAuditLogs_PageCap(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if int(atomic.AddInt32(&calls, 1)) > dropboxAuditMaxPages {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ev := map[string]interface{}{
			"timestamp":  "2024-01-01T10:00:00Z",
			"event_type": map[string]interface{}{".tag": "file_add", "description": "Added file"},
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"events":   []map[string]interface{}{ev},
			"cursor":   "more",
			"has_more": true,
		})
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
	if got := atomic.LoadInt32(&calls); got != int32(dropboxAuditMaxPages) {
		t.Fatalf("requests = %d; want %d (loop must stop at the page cap)", got, dropboxAuditMaxPages)
	}
}
