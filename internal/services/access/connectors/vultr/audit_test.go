package vultr

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// partialErrReader yields data once, then fails with a non-EOF transport
// error to emulate a connection reset mid-stream.
type partialErrReader struct {
	data []byte
	off  int
	err  error
}

func (r *partialErrReader) Read(p []byte) (int, error) {
	if r.off < len(r.data) {
		n := copy(p, r.data[r.off:])
		r.off += n
		return n, nil
	}
	return 0, r.err
}

func (r *partialErrReader) Close() error { return nil }

// TestReadVultrAuditBody_PropagatesReadError guards defect class #7
// (error swallowing): a genuine transport read failure must surface as an
// error, not be silently treated as a complete body. Returning a truncated
// page as success would drop audit events while still allowing the watermark
// to advance.
func TestReadVultrAuditBody_PropagatesReadError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       &partialErrReader{data: []byte(`{"audit_logs":[`), err: io.ErrUnexpectedEOF},
	}
	body, err := readVultrAuditBody(resp)
	if err == nil {
		t.Fatalf("expected read error to propagate, got nil (body=%q)", string(body))
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error = %v, want wrapped io.ErrUnexpectedEOF", err)
	}
}

func vultrAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "vultr-key"}
}

func TestVultrFetchAccessAuditLogs_Maps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v2/audit-log") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"audit_logs": []map[string]interface{}{
				{
					"id":          "evt-1",
					"type":        "instance.create",
					"description": "Instance created",
					"user_id":     "u-1",
					"user_name":   "admin@example.com",
					"ip":          "203.0.113.1",
					"timestamp":   "2024-09-01T10:00:00Z",
				},
			},
			"meta": map[string]interface{}{"links": map[string]interface{}{}},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, vultrAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 || collected[0].IPAddress != "203.0.113.1" {
		t.Fatalf("collected = %+v", collected)
	}
	if !nextSince.Equal(time.Date(2024, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("nextSince = %s", nextSince)
	}
}

func TestVultrFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, vultrAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
}
