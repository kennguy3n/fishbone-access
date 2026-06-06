package docusign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: when a sweep produces no new entries (empty response or every
// entry filtered by `since`), FetchAccessAuditLogs must NOT invoke the
// handler. Calling it with an empty batch would persist a zero/unchanged
// cursor and repeat a no-op fetch on every subsequent sweep, matching the
// guard used by the other audit connectors in this family.
func TestFetchAccessAuditLogs_EmptyBatchSkipsHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"requestLogs":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	called := false
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error {
			called = true
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if called {
		t.Fatal("handler invoked with an empty batch; want skipped to avoid cursor poisoning")
	}
}
