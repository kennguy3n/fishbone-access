package netlify

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

// Regression: a single audit page whose JSON body exceeds 1 MiB must be read
// in full. The previous reader capped the body at 1 MiB and broke mid-stream,
// which truncated the JSON array and made decoding fail (silently dropping the
// rest of the page for high-activity tenants). Each page is bounded by
// per_page, so reading the whole body is safe.
func TestNetlifyFetchAccessAuditLogs_LargePageNotTruncated(t *testing.T) {
	const n = 60 // < per_page (100) so the fetch stops after one page
	padding := strings.Repeat("x", 20*1024)
	events := make([]map[string]interface{}, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, map[string]interface{}{
			"id":         "evt-" + string(rune('A'+i%26)) + strings.Repeat("0", 4) + itoa(i),
			"account_id": "acme",
			"action":     "user.invited",
			"actor_id":   "u-1",
			"actor_name": padding,
			"log_type":   "user",
			"created_at": "2024-09-01T10:00:00Z",
		})
	}
	body, _ := json.Marshal(events)
	if len(body) <= 1<<20 {
		t.Fatalf("test fixture too small: %d bytes; want > 1 MiB", len(body))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), netlifyAuditConfig(), netlifyAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != n {
		t.Fatalf("collected %d events; want %d (page truncated?)", len(collected), n)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
