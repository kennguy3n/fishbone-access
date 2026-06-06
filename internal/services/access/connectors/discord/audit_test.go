package discord

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

// snowflake builds a Discord snowflake whose timestamp is at the
// supplied UTC instant.
func snowflake(ts time.Time) string {
	ms := ts.UTC().UnixMilli() - discordEpochMs
	if ms < 0 {
		ms = 0
	}
	return fmt.Sprintf("%d", uint64(ms)<<22)
}

func TestDiscordFetchAccessAuditLogs_MapsAndFiltersBySince(t *testing.T) {
	older := snowflake(time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC))
	newer := snowflake(time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/audit-logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bot ") {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"audit_log_entries": []map[string]interface{}{
				{"id": newer, "user_id": "user-1", "target_id": "tgt-1", "action_type": 20},
				{"id": older, "user_id": "user-2", "target_id": "tgt-2", "action_type": 50},
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var collected []*access.AuditLogEntry
	var lastSince time.Time
	since := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: since},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			collected = append(collected, batch...)
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("len = %d; want 1 (older entry must be filtered by since)", len(collected))
	}
	if collected[0].EventType != "member_change" {
		t.Errorf("event_type = %s; want member_change", collected[0].EventType)
	}
	if !lastSince.After(since) {
		t.Errorf("lastSince = %s; want > since", lastSince)
	}
}

func TestDiscordFetchAccessAuditLogs_NotAvailableOnForbidden(t *testing.T) {
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

func TestDiscordFetchAccessAuditLogs_ServerError(t *testing.T) {
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

// TestDiscordFetchAccessAuditLogs_PaginationFailureDoesNotAdvanceCursor
// pins the buffer-then-emit-once invariant: when a multi-page sweep
// fails between pages, the handler must never be invoked. The worker
// persists `nextSince` even on partial failure, so any handler call
// on a partial sweep would advance the cursor past entries the
// connector never returned and the missing entries would be lost on
// the next run (the new cursor's `since` filter would skip them).
func TestDiscordFetchAccessAuditLogs_PaginationFailureDoesNotAdvanceCursor(t *testing.T) {
	baseTS := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	page := make([]map[string]interface{}, 0, discordAuditPageSize)
	for i := 0; i < discordAuditPageSize; i++ {
		page = append(page, map[string]interface{}{
			"id":          snowflake(baseTS.Add(-time.Duration(i) * time.Minute)),
			"user_id":     "user-1",
			"target_id":   "tgt-1",
			"action_type": 20,
		})
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"audit_log_entries": page,
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
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
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
