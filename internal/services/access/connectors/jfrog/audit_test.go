package jfrog

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

func jfrogAuditConfig(base string) map[string]interface{} {
	return map[string]interface{}{"base_url": base}
}
func jfrogAuditSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "jfrog.access.token"}
}

func TestJFrogFetchAccessAuditLogs_MapsAndPaginates(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/access/api/v2/events" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		offset := r.URL.Query().Get("offset")
		body := map[string]interface{}{"total": 101}
		if calls == 1 {
			if offset != "0" {
				t.Errorf("offset = %q", offset)
			}
			events := []map[string]interface{}{}
			for i := 0; i < 100; i++ {
				events = append(events, map[string]interface{}{
					"id":          "evt-" + indexStr(i),
					"event_type":  "user.login",
					"action":      "login",
					"timestamp":   "2024-03-01T0" + indexStr(i%9) + ":00:00Z",
					"username":    "alice",
					"user_email":  "alice@example.com",
					"user_id":     "u-1",
					"ip_address":  "203.0.113.5",
					"target_id":   "platform",
					"target_type": "platform",
				})
			}
			body["events"] = events
		} else {
			if offset != "100" {
				t.Errorf("offset = %q", offset)
			}
			body["events"] = []map[string]interface{}{
				{
					"id":          "evt-final",
					"event_type":  "group.create",
					"action":      "create",
					"timestamp":   "2024-03-01T10:00:00Z",
					"username":    "bob",
					"user_id":     "u-2",
					"target_id":   "developers",
					"target_type": "group",
				},
			}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var nextSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), jfrogAuditConfig(srv.URL), jfrogAuditSecrets(),
		map[string]time.Time{},
		func(batch []*access.AuditLogEntry, n time.Time, _ string) error {
			collected = append(collected, batch...)
			nextSince = n
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 101 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[100].EventID != "evt-final" || collected[100].TargetType != "group" {
		t.Errorf("last = %+v", collected[100])
	}
	want := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)
	if !nextSince.Equal(want) {
		t.Errorf("nextSince = %s, want %s", nextSince, want)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestJFrogFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), jfrogAuditConfig(srv.URL), jfrogAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestJFrogFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	called := false
	err := c.FetchAccessAuditLogs(context.Background(), jfrogAuditConfig(srv.URL), jfrogAuditSecrets(),
		map[string]time.Time{},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { called = true; return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v", err)
	}
	if called {
		t.Error("handler should not be called on error")
	}
}

func indexStr(i int) string {
	if i < 0 {
		return "0"
	}
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// errReadCloser yields data and then fails the next Read with a non-EOF error,
// simulating a connection reset / context cancellation mid-body.
type errReadCloser struct {
	data []byte
	pos  int
	err  error
}

func (r *errReadCloser) Read(p []byte) (int, error) {
	if r.pos < len(r.data) {
		n := copy(p, r.data[r.pos:])
		r.pos += n
		return n, nil
	}
	return 0, r.err
}

func (r *errReadCloser) Close() error { return nil }

// TestReadJFrogBody_SurfacesReadError is a regression guard: readJFrogBody must
// propagate non-EOF read failures rather than returning (truncatedBody, nil).
// Swallowing the error let a partially-read page JSON-unmarshal into a shorter
// slice, which advanced the audit cursor past events that were never seen
// (silent audit data loss). The manual read loop returned nil unconditionally,
// making the caller's `if readErr != nil` check dead code.
func TestReadJFrogBody_SurfacesReadError(t *testing.T) {
	wantErr := errors.New("connection reset by peer")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       &errReadCloser{data: []byte(`{"events":[{"id":"e1"}`), err: wantErr},
	}
	_, err := readJFrogBody(resp)
	if err == nil {
		t.Fatal("readJFrogBody returned nil error on a mid-body read failure; want the underlying error surfaced so a truncated page is not treated as complete")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("readJFrogBody error = %v; want it to wrap %v", err, wantErr)
	}
}
