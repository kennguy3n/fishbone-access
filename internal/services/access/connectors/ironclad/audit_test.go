package ironclad

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// errBody is a response body whose Read fails after returning the opening
// bytes, simulating a connection reset / TLS error mid-stream.
type errBody struct{ read bool }

func (b *errBody) Read(p []byte) (int, error) {
	if !b.read {
		b.read = true
		p[0] = '{'
		return 1, nil
	}
	return 0, errors.New("simulated connection reset")
}
func (b *errBody) Close() error { return nil }

// errDoer returns a 200 response whose body errors mid-read.
type errDoer struct{}

func (errDoer) Do(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       &errBody{},
	}, nil
}

func TestIroncladFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/api/v1/audit-logs" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer token")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"audit_logs": []map[string]interface{}{{
				"id":          "evt-1",
				"event_type":  "workflow.signed",
				"action":      "sign",
				"timestamp":   "2024-09-01T10:00:00Z",
				"user_id":     "u-42",
				"user_email":  "counsel@example.com",
				"workflow_id": "wf-7",
				"ip_address":  "10.0.0.1",
			}},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].TargetExternalID != "wf-7" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestIroncladFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestIroncladFetchAccessAuditLogs_TransientFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}

// TestIroncladFetchAccessAuditLogs_EmitsPerPage proves the connector invokes the
// handler once per provider page (AccessAuditor contract) instead of buffering
// every page and emitting a single batch. A full first page forces a second
// request; the handler must therefore be called at least twice with a
// monotonically non-decreasing nextSince. Fails against the buffer-then-emit
// implementation, which calls the handler exactly once.
func TestIroncladFetchAccessAuditLogs_EmitsPerPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			logs := make([]map[string]interface{}, ironcladAuditPageSize)
			for i := range logs {
				logs[i] = map[string]interface{}{
					"id":         fmt.Sprintf("evt-%d", i),
					"event_type": "workflow.signed",
					"timestamp":  time.Date(2024, 9, 1, 0, 0, i, 0, time.UTC).Format(time.RFC3339),
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": logs})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": []map[string]interface{}{{
			"id":         "evt-last",
			"event_type": "workflow.signed",
			"timestamp":  "2024-09-02T10:00:00Z",
		}}})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var calls, total int
	var last time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			calls++
			total += len(batch)
			if n.Before(last) {
				t.Errorf("nextSince regressed: %s < %s", n, last)
			}
			last = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls < 2 {
		t.Fatalf("handler called %d time(s); want one call per page (>=2)", calls)
	}
	if total != ironcladAuditPageSize+1 {
		t.Fatalf("total entries = %d; want %d", total, ironcladAuditPageSize+1)
	}
	if !last.Equal(time.Date(2024, 9, 2, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("final nextSince = %s; want 2024-09-02T10:00:00Z", last)
	}
}

// TestIroncladFetchAccessAuditLogs_SurfacesReadError is a regression guard for
// the read-error-swallowing class: a body that fails mid-read must abort the
// sweep with a non-nil error rather than be treated as a (short/empty) page,
// which would silently advance the cursor past unseen events. Representative
// of the shared fix applied across the batch's audit readers.
func TestIroncladFetchAccessAuditLogs_SurfacesReadError(t *testing.T) {
	c := New()
	c.urlOverride = "https://ironclad.example"
	c.httpClient = func() httpDoer { return errDoer{} }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error {
			t.Fatal("handler must not be called when the body read fails")
			return nil
		})
	if err == nil {
		t.Fatal("err = nil; want the read error surfaced, not swallowed")
	}
	if !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("err = %v; want it to wrap the underlying read error", err)
	}
}
