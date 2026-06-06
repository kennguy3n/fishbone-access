package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func tsAuditConfig() map[string]interface{} {
	return map[string]interface{}{"tailnet": "acme.org"}
}
func tsAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "tskey-api-abc"}
}

func TestTailscaleFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/tailnet/acme.org/logging/configuration") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"logs": []map[string]interface{}{
				{
					"eventId":   "evt-1",
					"action":    "UPDATE",
					"origin":    "admin-console",
					"eventTime": "2024-09-01T10:00:00Z",
					"actor": map[string]string{
						"id":          "u-1",
						"loginName":   "admin@example.com",
						"displayName": "Admin",
						"type":        "user",
					},
					"target": map[string]string{
						"id":   "tag:prod",
						"type": "tag",
						"name": "prod",
					},
				},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2024, 9, 1, 12, 0, 0, 0, time.UTC) }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), tsAuditConfig(), tsAuditSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].ActorEmail != "admin@example.com" || collected[0].TargetType != "tag" {
		t.Errorf("entry = %+v", collected[0])
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestTailscaleFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), tsAuditConfig(), tsAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestTailscaleFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), tsAuditConfig(), tsAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

// A 2xx body larger than the read cap is reported as an explicit
// truncation error (the endpoint is not paginated), rather than being
// silently truncated into an opaque JSON decode failure.
func TestTailscaleFetchAccessAuditLogs_Truncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Emit a syntactically valid JSON document whose length exceeds
		// the cap, so the failure is unambiguously truncation rather
		// than a malformed payload.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"logs":[`))
		_, _ = w.Write([]byte(strings.Repeat(" ", tsAuditBodyCap+16)))
		_, _ = w.Write([]byte(`]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	called := false
	err := c.FetchAccessAuditLogs(context.Background(), tsAuditConfig(), tsAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { called = true; return nil })
	if err == nil {
		t.Fatalf("expected truncation error, got nil")
	}
	if errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("truncation must not collapse to ErrAuditNotAvailable: %v", err)
	}
	if !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), "narrow") {
		t.Fatalf("error should be an actionable truncation message, got: %v", err)
	}
	if strings.Contains(err.Error(), "decode") {
		t.Fatalf("truncation must be distinguished from a decode failure, got: %v", err)
	}
	if called {
		t.Fatalf("handler must not be invoked on a truncated response")
	}
}
