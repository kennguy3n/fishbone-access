package lastpass

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		if parsed["cmd"] != "reporting" {
			t.Errorf("cmd = %v; want reporting", parsed["cmd"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"0": {"Time": "2024-09-01 08:00:00", "Username": "alice@example.com", "IP_Address": "10.0.0.1", "Action": "Login"},
			"1": {"Time": "2024-09-01 09:00:00", "Username": "bob@example.com", "IP_Address": "10.0.0.2", "Action": "PasswordChange"}
		}`))
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d; want 2", len(collected))
	}
	got := map[string]string{}
	for _, e := range collected {
		got[e.ActorEmail] = e.EventType
	}
	if got["alice@example.com"] != "Login" {
		t.Errorf("alice EventType = %q", got["alice@example.com"])
	}
	if got["bob@example.com"] != "PasswordChange" {
		t.Errorf("bob EventType = %q", got["bob@example.com"])
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"FAIL","error":"insufficient privileges"}`))
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

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected provider error")
	}
	if err == access.ErrAuditNotAvailable {
		t.Fatalf("err = ErrAuditNotAvailable; want generic error")
	}
}

func TestFetchAccessAuditLogs_GenericFailIsNotPlanGated(t *testing.T) {
	// LastPass returns status:"FAIL" for many transient and
	// parameter-level errors (rate limits, malformed args, backend
	// outages). Those must bubble up as ordinary errors so the sync
	// retries — not be classified silently as ErrAuditNotAvailable.
	cases := []string{
		`{"status":"FAIL","error":"rate limit exceeded"}`,
		`{"status":"FAIL","error":"invalid date range"}`,
		`{"status":"FAIL","error":"temporary failure"}`,
	}
	for _, body := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}))
		c := New()
		c.urlOverride = server.URL
		c.httpClient = func() httpDoer { return server.Client() }
		err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
			map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
			func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
		server.Close()
		if err == nil {
			t.Errorf("body %q: err = nil; want generic provider error", body)
			continue
		}
		if err == access.ErrAuditNotAvailable {
			t.Errorf("body %q: err = ErrAuditNotAvailable; want generic error (no plan-gating marker)", body)
		}
	}
}

func TestFetchAccessAuditLogs_PermissionFailIsPlanGated(t *testing.T) {
	// Conversely, FAIL responses whose error names a permission /
	// plan condition must still be classified as plan-gated.
	cases := []string{
		`{"status":"FAIL","error":"Not authorized"}`,
		`{"status":"FAIL","error":"License required for cmd=reporting"}`,
		`{"status":"FAIL","error":"Subscription required"}`,
	}
	for _, body := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}))
		c := New()
		c.urlOverride = server.URL
		c.httpClient = func() httpDoer { return server.Client() }
		err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
			map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
			func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
		server.Close()
		if err != access.ErrAuditNotAvailable {
			t.Errorf("body %q: err = %v; want ErrAuditNotAvailable", body, err)
		}
	}
}

func TestFetchAccessAuditLogs_ArrayResponseDecodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Time":"2024-09-01 10:00:00","Username":"c@example.com","Action":"AdminUserAdded"}]`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(), nil,
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].EventType != "AdminUserAdded" {
		t.Fatalf("collected = %+v", collected)
	}
}

// TestFetchAccessAuditLogs_EmptyResponseSkipsHandler guards the cursor
// contract: when the reporting API returns no events the handler must
// not be called, otherwise it would persist nextSince=zero-time and
// regress the audit cursor to epoch (re-ingesting old events).
func TestFetchAccessAuditLogs_EmptyResponseSkipsHandler(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }
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
		t.Fatal("handler called with empty batch; cursor could regress to epoch")
	}
}
