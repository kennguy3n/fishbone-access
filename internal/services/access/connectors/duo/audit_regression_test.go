package duo

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

// Regression: a provider that keeps returning a non-empty next_offset must not
// spin the pagination loop forever. The sweep is bounded by duoAuditMaxPages.
// The mock returns a hard error on the (cap+1)-th request so that, without the
// cap, the test fails loudly instead of hanging.
func TestFetchAccessAuditLogs_PageCap(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if int(atomic.AddInt32(&calls, 1)) > duoAuditMaxPages {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"stat": "OK",
			"response": map[string]interface{}{
				"authlogs": []map[string]interface{}{
					{
						"txid":         "tx",
						"event_type":   "authentication",
						"result":       "success",
						"isotimestamp": "2024-07-01T08:00:00.000Z",
						"user":         map[string]interface{}{"key": "u1", "name": "alice@example.com"},
					},
				},
				"metadata": map[string]interface{}{"next_offset": "keep-going"},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != int32(duoAuditMaxPages) {
		t.Fatalf("requests = %d; want %d (loop must stop at the page cap)", got, duoAuditMaxPages)
	}
}
