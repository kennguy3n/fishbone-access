package trello

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

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/organizations/org123/actions") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("key") == "" || r.URL.Query().Get("token") == "" {
			t.Errorf("missing key/token query params")
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":              "act-newer",
				"type":            "addMemberToOrganization",
				"date":            "2024-01-01T11:00:00.000Z",
				"idMemberCreator": "actor-1",
				"data": map[string]interface{}{
					"member": map[string]interface{}{
						"id":       "mem-9",
						"username": "alice",
					},
				},
			},
			{
				"id":              "act-older",
				"type":            "createBoard",
				"date":            "2024-01-01T10:00:00.000Z",
				"idMemberCreator": "actor-2",
				"data": map[string]interface{}{
					"board": map[string]interface{}{
						"id":   "board-77",
						"name": "Roadmap",
					},
				},
			},
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
	if len(collected) != 2 {
		t.Fatalf("len = %d", len(collected))
	}
	// After reversal, older entry should come first.
	if collected[0].EventID != "act-older" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[0].TargetExternalID != "board-77" || collected[0].TargetType != "board" {
		t.Errorf("entry 0 target = %+v", collected[0])
	}
	if collected[1].EventID != "act-newer" {
		t.Errorf("entry 1 = %+v", collected[1])
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

func TestFetchAccessAuditLogs_ProviderError(t *testing.T) {
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
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
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

// TestFetchAccessAuditLogs_MultiPageAscendingCursor verifies that
// when the provider paginates reverse-chronologically across
// multiple pages, the connector collects every page first and then
// emits a single chronologically-ascending batch with `nextSince`
// set to the global maximum. This is the regression test for the
// monotonic-cursor contract: the handler must never receive a
// `nextSince` that covers events not yet yielded to it (see
// internal/workers/handlers/access_audit.go:124-132).
func TestFetchAccessAuditLogs_MultiPageAscendingCursor(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		switch n {
		case 1:
			if r.URL.Query().Get("before") != "" {
				t.Errorf("call 1: unexpected before=%q", r.URL.Query().Get("before"))
			}
			// Page 1: newest 50 events, timestamps T+50 → T+1.
			page := make([]map[string]interface{}, 0, trelloAuditPageSize)
			for i := trelloAuditPageSize; i >= 1; i-- {
				page = append(page, map[string]interface{}{
					"id":              fmt.Sprintf("act-%03d", i),
					"type":            "updateCard",
					"date":            time.Date(2024, 1, 1, 0, i, 0, 0, time.UTC).Format(time.RFC3339Nano),
					"idMemberCreator": fmt.Sprintf("actor-%d", i),
				})
			}
			_ = json.NewEncoder(w).Encode(page)
		case 2:
			// Page 2: must be requested with before=<oldest id of page 1>.
			if got := r.URL.Query().Get("before"); got != "act-001" {
				t.Errorf("call 2: before = %q, want act-001", got)
			}
			// Older 5 events, timestamps T+0 → T-4 (chronologically
			// *before* page 1's window). Page is shorter than
			// pageSize so the sweep terminates after this page.
			page := []map[string]interface{}{
				{"id": "act-000", "type": "createCard", "date": "2024-01-01T00:00:00.000Z", "idMemberCreator": "actor-0"},
				{"id": "act-X-1", "type": "createCard", "date": "2023-12-31T23:59:00.000Z", "idMemberCreator": "actor-1"},
				{"id": "act-X-2", "type": "createCard", "date": "2023-12-31T23:58:00.000Z", "idMemberCreator": "actor-2"},
				{"id": "act-X-3", "type": "createCard", "date": "2023-12-31T23:57:00.000Z", "idMemberCreator": "actor-3"},
				{"id": "act-X-4", "type": "createCard", "date": "2023-12-31T23:56:00.000Z", "idMemberCreator": "actor-4"},
			}
			_ = json.NewEncoder(w).Encode(page)
		default:
			t.Errorf("unexpected call %d", n)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var handlerCalls int
	var batch []*access.AuditLogEntry
	var lastSince time.Time
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC)},
		func(b []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			handlerCalls++
			batch = b
			lastSince = nextSince
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler called %d times, want exactly 1 after full sweep", handlerCalls)
	}
	if got, want := len(batch), trelloAuditPageSize+5; got != want {
		t.Fatalf("batch size = %d, want %d", got, want)
	}
	// Batch must be chronologically ascending so the global max
	// timestamp lands at the tail — i.e. cursor never advances past
	// an event not yet in the batch.
	for i := 1; i < len(batch); i++ {
		if batch[i].Timestamp.Before(batch[i-1].Timestamp) {
			t.Fatalf("batch not chronological at i=%d: %s before %s",
				i, batch[i].Timestamp, batch[i-1].Timestamp)
		}
	}
	wantMax := time.Date(2024, 1, 1, 0, trelloAuditPageSize, 0, 0, time.UTC)
	if !lastSince.Equal(wantMax) {
		t.Errorf("lastSince = %s, want %s (global max across pages)", lastSince, wantMax)
	}
	if !batch[len(batch)-1].Timestamp.Equal(lastSince) {
		t.Errorf("final batch event ts %s != lastSince %s", batch[len(batch)-1].Timestamp, lastSince)
	}
}

// TestFetchAccessAuditLogs_HandlerFailureDoesNotAdvanceCursor
// guarantees that when the downstream handler errors, the cursor
// it was offered does not falsely indicate progress past un-yielded
// events. Because the connector emits exactly one handler call per
// sweep (after collecting every page), a handler error on the very
// first call leaves the worker's persisted cursor untouched.
func TestFetchAccessAuditLogs_HandlerFailureDoesNotAdvanceCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":              "act-1",
				"type":            "updateCard",
				"date":            "2024-01-01T10:00:00.000Z",
				"idMemberCreator": "actor-1",
			},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	sentinel := errors.New("downstream publish failed")
	var handlerCalls int
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, nextSince time.Time, _ string) error {
			handlerCalls++
			// Every event in the batch must lie at or before the
			// `nextSince` we're being offered — if the connector
			// ever offers a cursor past un-yielded events, the
			// worker will silently skip them on retry.
			for _, e := range batch {
				if e.Timestamp.After(nextSince) {
					t.Errorf("event ts %s > nextSince %s", e.Timestamp, nextSince)
				}
			}
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler called %d times, want exactly 1", handlerCalls)
	}
}
