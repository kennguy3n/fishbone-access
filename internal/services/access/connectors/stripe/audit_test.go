package stripe

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

func validStripeSecrets() map[string]interface{} {
	return map[string]interface{}{"secret_key": "sk_test_abc123"}
}

func TestStripeFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	// Stripe `/v1/events` paginates reverse-chronologically: page 1 is
	// the newest event, `starting_after` walks backwards in time so
	// page 2 contains older events.
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"object":   "list",
				"has_more": true,
				"data": []map[string]interface{}{
					{
						"id":      "evt_2",
						"type":    "account.updated",
						"created": time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC).Unix(),
						"account": "acct_1",
					},
				},
			})
		case 1:
			call++
			if r.URL.Query().Get("starting_after") != "evt_2" {
				t.Errorf("starting_after = %s", r.URL.Query().Get("starting_after"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"object":   "list",
				"has_more": false,
				"data": []map[string]interface{}{
					{
						"id":      "evt_1",
						"type":    "customer.created",
						"created": time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC).Unix(),
						"account": "acct_1",
						"request": map[string]interface{}{"id": "req_1"},
					},
				},
			})
		default:
			t.Errorf("unexpected call %d", call)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, validStripeSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error {
			if partitionKey != access.DefaultAuditPartition {
				t.Errorf("partitionKey = %q", partitionKey)
			}
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].EventType != "customer.created" || collected[0].Action != "created" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

func TestStripeFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, validStripeSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestStripeFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, validStripeSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-nil non-ErrAuditNotAvailable", err)
	}
}

// TestStripeFetchAccessAuditLogs_PaginationFailureDoesNotAdvanceCursor
// guards against the data-loss bug where a per-page handler call would
// persist `nextSince` at the newest timestamp on page 1, stranding the
// older un-yielded entries below the persisted cursor if page 2 failed.
// With the buffer-then-emit-once pattern the handler is never called
// during pagination, so a failure on any page surfaces as an error
// without advancing the cursor.
func TestStripeFetchAccessAuditLogs_PaginationFailureDoesNotAdvanceCursor(t *testing.T) {
	baseTS := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	page := make([]map[string]interface{}, 0, pageSize)
	for i := 0; i < pageSize; i++ {
		page = append(page, map[string]interface{}{
			"id":      fmt.Sprintf("evt_%d", i),
			"type":    "customer.created",
			"created": baseTS.Add(-time.Duration(i) * time.Minute).Unix(),
			"account": "acct_1",
		})
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"object":   "list",
				"has_more": true,
				"data":     page,
			})
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	handlerCalls := 0
	err := c.FetchAccessAuditLogs(context.Background(), map[string]interface{}{}, validStripeSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error {
			handlerCalls++
			return nil
		})
	if err == nil {
		t.Fatalf("err = nil; want non-nil (page 2 returned 500)")
	}
	if errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v; 500 must not collapse to ErrAuditNotAvailable", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v; want a 500 status error", err)
	}
	if handlerCalls != 0 {
		t.Fatalf("handler must not be invoked when pagination fails; got %d call(s)", handlerCalls)
	}
	if calls != 2 {
		t.Fatalf("expected 2 HTTP calls (page 1 OK, page 2 500), got %d", calls)
	}
}
