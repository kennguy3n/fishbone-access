package mailchimp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestMailchimpFetchAccessAuditLogs_MapsChatter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/3.0/activity-feed/chimp-chatter") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"chimp_chatter": []map[string]interface{}{
				{
					"type":        "campaigns:campaign-sent",
					"title":       "Campaign sent",
					"message":     "Weekly newsletter sent to 5,000 subscribers",
					"update_time": "2024-01-01T11:00:00Z",
					"campaign_id": "camp-9",
					"list_id":     "list-1",
				},
			},
			"total_items": 1,
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d", len(collected))
	}
	if collected[0].EventType != "campaigns:campaign-sent" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

func TestMailchimpFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if !errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want ErrAuditNotAvailable", err)
	}
}

func TestMailchimpFetchAccessAuditLogs_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-nil non-ErrAuditNotAvailable", err)
	}
}

// TestMailchimpFetchAccessAuditLogs_PaginatesNewestFirst exercises the
// buffer-then-emit-once pattern under Mailchimp's reverse-chronological
// pagination. Page 1 returns the newer event (12:00), page 2 returns the
// older one (10:00), and the handler must be called exactly once with a
// chronologically ascending batch and `nextSince` set to the maximum
// timestamp across all pages.
func TestMailchimpFetchAccessAuditLogs_PaginatesNewestFirst(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		offset := r.URL.Query().Get("offset")
		switch n {
		case 1:
			if offset != "0" {
				t.Errorf("call 1 offset = %q, want 0", offset)
			}
			page := map[string]interface{}{
				"chimp_chatter": fillChatter(mailchimpAuditPageSize, time.Date(2024, 1, 1, 12, 59, 59, 0, time.UTC), "newer"),
				"total_items":   2 * mailchimpAuditPageSize,
			}
			_ = json.NewEncoder(w).Encode(page)
		case 2:
			if offset != fmt.Sprintf("%d", mailchimpAuditPageSize) {
				t.Errorf("call 2 offset = %q, want %d", offset, mailchimpAuditPageSize)
			}
			// Page 2 returns fewer than page-size entries, terminating
			// the sweep without requiring a third call.
			page := map[string]interface{}{
				"chimp_chatter": []map[string]interface{}{
					{
						"type":        "campaigns:campaign-sent",
						"title":       "Older campaign",
						"message":     "Older newsletter",
						"update_time": "2024-01-01T10:00:00Z",
						"campaign_id": "older",
					},
				},
				"total_items": 2 * mailchimpAuditPageSize,
			}
			_ = json.NewEncoder(w).Encode(page)
		default:
			t.Errorf("unexpected call %d", n)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var handlerCalls int
	var collected []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			handlerCalls++
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler invocations = %d, want 1", handlerCalls)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("http calls = %d, want 2", calls)
	}
	if got, want := len(collected), mailchimpAuditPageSize+1; got != want {
		t.Fatalf("collected len = %d, want %d", got, want)
	}
	// First emitted entry must be the older one (chronologically
	// ascending), last entry must be one of the newer page-1 entries.
	if got := collected[0].TargetExternalID; got != "older" {
		t.Errorf("collected[0].target = %q, want older", got)
	}
	lastTS := collected[len(collected)-1].Timestamp
	for i, e := range collected[1:] {
		if e.Timestamp.Before(collected[i].Timestamp) {
			t.Errorf("collected[%d] is not chronologically ascending: %s before %s", i+1, e.Timestamp, collected[i].Timestamp)
		}
	}
	if !lastSince.Equal(lastTS) {
		t.Errorf("lastSince = %s, want %s", lastSince, lastTS)
	}
	wantMax := time.Date(2024, 1, 1, 12, 59, 59, 0, time.UTC)
	if !lastTS.Equal(wantMax) {
		t.Errorf("max ts = %s, want %s", lastTS, wantMax)
	}
}

// TestMailchimpFetchAccessAuditLogs_PaginationFailureDoesNotAdvanceCursor
// guards the buffer-then-emit-once contract: if page 2 fails before the
// full sweep completes, the handler must never be invoked so the
// worker's persisted cursor stays below the un-yielded older entries.
// Without buffering, page 1 would have emitted its newer entries first
// and advanced the cursor past them, permanently stranding the older
// page-2 entries on retry.
func TestMailchimpFetchAccessAuditLogs_PaginationFailureDoesNotAdvanceCursor(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		switch n {
		case 1:
			page := map[string]interface{}{
				"chimp_chatter": fillChatter(mailchimpAuditPageSize, time.Date(2024, 1, 1, 12, 59, 59, 0, time.UTC), "p1"),
				"total_items":   2 * mailchimpAuditPageSize,
			}
			_ = json.NewEncoder(w).Encode(page)
		case 2:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"detail":"upstream blip"}`))
		default:
			t.Errorf("unexpected call %d", n)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var handlerCalls int
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error {
			handlerCalls++
			return nil
		})
	if err == nil {
		t.Fatalf("err = nil, want non-nil (page 2 failed with 500)")
	}
	if errors.Is(err, access.ErrAuditNotAvailable) {
		t.Fatalf("err = %v, want non-ErrAuditNotAvailable", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want it to mention HTTP 500", err)
	}
	if handlerCalls != 0 {
		t.Fatalf("handler invocations = %d, want 0 — page-2 failure must never emit cursor advancement", handlerCalls)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("http calls = %d, want 2", got)
	}
}

// fillChatter returns n chimp-chatter entries with strictly
// monotonically decreasing timestamps anchored at `base`. The entries
// are returned in reverse-chronological order (newest first), matching
// Mailchimp's documented chimp-chatter feed ordering.
func fillChatter(n int, base time.Time, target string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, n)
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(-i) * time.Second).UTC()
		out = append(out, map[string]interface{}{
			"type":        "campaigns:campaign-sent",
			"title":       fmt.Sprintf("evt-%d", i),
			"message":     "page-fill entry",
			"update_time": ts.Format(time.RFC3339),
			"campaign_id": fmt.Sprintf("%s-%d", target, i),
		})
	}
	return out
}

// TestMailchimpFetchAccessAuditLogs_EventIDNoWhitespace guards that the
// derived EventID never contains the space Mailchimp emits in its
// "2006-01-02 15:04:05" timestamp format. The ID prefix must use the
// parsed/canonicalized timestamp so downstream systems that URL-encode or
// split on whitespace receive a stable, space-free key.
func TestMailchimpFetchAccessAuditLogs_EventIDNoWhitespace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"chimp_chatter": []map[string]interface{}{
				{
					"type":        "campaigns:campaign-sent",
					"title":       "Campaign sent",
					"message":     "Weekly newsletter",
					"update_time": "2024-01-01 11:00:00",
					"campaign_id": "camp-9",
				},
			},
			"total_items": 1,
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d", len(collected))
	}
	if id := collected[0].EventID; strings.ContainsAny(id, " \t\n") {
		t.Errorf("EventID %q contains whitespace", id)
	}
}
