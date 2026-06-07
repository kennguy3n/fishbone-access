package workday

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
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/ccx/api/v1/acme1/activityLogging") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer wdAAAA1234bbbbCCCC" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		// Emit `pageSize` rows on the first page and 1 row on the second
		// so the loop is forced to round-trip both.
		switch call {
		case 0:
			if r.URL.Query().Get("offset") != "0" {
				t.Errorf("offset = %s", r.URL.Query().Get("offset"))
			}
			call++
			rows := make([]map[string]interface{}, 0, pageSize)
			rows = append(rows, map[string]interface{}{
				"id":             "act-1",
				"activityAction": "Sign On",
				"requestTime":    "2024-01-01T10:00:00.123Z",
				"userId":         "user-1",
				"userName":       "alice@acme.com",
				"ipAddress":      "203.0.113.1",
			})
			for i := 1; i < pageSize; i++ {
				rows = append(rows, map[string]interface{}{
					"id":             "act-filler-" + strings.Repeat("x", i%4),
					"activityAction": "View",
					"requestTime":    "2024-01-01T10:30:00Z",
				})
			}
			// Ensure first entry's filler ID is unique enough by overriding
			rows[0]["id"] = "act-1"
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": rows})
		case 1:
			if r.URL.Query().Get("offset") == "0" {
				t.Errorf("page2 offset = %s", r.URL.Query().Get("offset"))
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":             "act-final",
						"activityAction": "Sign Off",
						"requestTime":    "2024-01-01T11:00:00Z",
						"userId":         "user-2",
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
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
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
	if len(collected) < 2 {
		t.Fatalf("len = %d, want at least 2", len(collected))
	}
	if collected[0].EventType != "Sign On" || collected[0].ActorExternalID != "user-1" || collected[0].IPAddress != "203.0.113.1" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[0].Timestamp.IsZero() {
		t.Errorf("entry 0 timestamp zero")
	}
	want := time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC)
	if !lastSince.Equal(want) {
		t.Errorf("lastSince = %s, want %s", lastSince, want)
	}
}

// TestMapWorkdayActivity_DropsZeroTimestamp guards against zero-timestamp
// poisoning: when requestTime is missing or unparseable, parseWorkdayTime
// returns the zero time. Emitting such an entry writes a 0001-01-01 timestamp
// into the audit store (corrupt watermark data). The mapper must drop the
// event — matching every sibling connector's audit mapper.
func TestMapWorkdayActivity_DropsZeroTimestamp(t *testing.T) {
	if got := mapWorkdayActivity(&workdayActivityRow{ID: "act-x", ActivityAction: "Sign On"}); got != nil {
		t.Errorf("empty requestTime: got %+v, want nil", got)
	}
	if got := mapWorkdayActivity(&workdayActivityRow{ID: "act-y", ActivityAction: "Sign On", RequestTime: "not-a-timestamp"}); got != nil {
		t.Errorf("unparseable requestTime: got %+v, want nil", got)
	}
	if got := mapWorkdayActivity(&workdayActivityRow{ID: "act-z", ActivityAction: "Sign On", RequestTime: "2024-01-01T10:00:00Z"}); got == nil {
		t.Error("valid requestTime: got nil, want entry")
	}
}

// TestParseWorkdayTime_NormalizesToUTC guards watermark stability: the
// audit cursor (batchMax) is derived from parsed event timestamps, so a
// non-UTC location would leak into the persisted watermark and could drift
// across serialize/deserialize round-trips. Every sibling audit parser
// normalizes to UTC; this one must too.
func TestParseWorkdayTime_NormalizesToUTC(t *testing.T) {
	cases := []string{
		"2024-09-01T10:00:00+05:00",     // RFC3339 with offset
		"2024-09-01T10:00:00.250-08:00", // RFC3339Nano with offset
		"2024-09-01T10:00:00Z",          // already UTC
	}
	for _, in := range cases {
		got := parseWorkdayTime(in)
		if got.IsZero() {
			t.Fatalf("parseWorkdayTime(%q) returned zero", in)
		}
		if got.Location() != time.UTC {
			t.Errorf("parseWorkdayTime(%q).Location() = %v, want UTC", in, got.Location())
		}
	}
}

// TestFetchAccessAuditLogs_CapsPages guards against an unbounded pagination
// loop: a misbehaving tenant whose `from` filter never advances past a full
// data window would keep returning full pages forever. The connector must stop
// after workdayAuditMaxPages instead of looping until the context times out.
// The server records over-runs so the test fails deterministically (no hang)
// without the cap.
func TestFetchAccessAuditLogs_CapsPages(t *testing.T) {
	var calls int32
	overran := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		// Safety net: if the connector ignores the cap, break the loop after a
		// few extra pages so the test fails on assertion instead of hanging.
		if int(n) > workdayAuditMaxPages+3 {
			overran = true
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{}})
			return
		}
		// Always return a FULL page (len == pageSize) with distinct, advancing
		// timestamps so len(page.Data) < limit never triggers termination.
		rows := make([]map[string]interface{}, 0, pageSize)
		base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(n) * time.Hour)
		for i := 0; i < pageSize; i++ {
			rows = append(rows, map[string]interface{}{
				"id":             fmt.Sprintf("act-%d-%d", n, i),
				"activityAction": "View",
				"requestTime":    base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": rows})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Time{}},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if overran {
		t.Fatalf("connector exceeded the %d-page cap (unbounded loop)", workdayAuditMaxPages)
	}
	if got := atomic.LoadInt32(&calls); int(got) != workdayAuditMaxPages {
		t.Fatalf("calls = %d, want exactly %d (max-page cap)", got, workdayAuditMaxPages)
	}
}

// TestFetchAccessAuditLogs_SkipsEmptyBatches guards against emitting an
// empty batch with a non-advancing cursor. When every row on a full page is
// filtered out (e.g. unparseable timestamps), the handler must NOT be invoked
// for that page — otherwise a caller could persist a stale watermark and
// re-fetch the same window. Pagination must still advance to the next page.
// This matches the sibling audit connectors, which only call the handler for
// non-empty batches.
func TestFetchAccessAuditLogs_SkipsEmptyBatches(t *testing.T) {
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch call {
		case 0:
			call++
			// A FULL page where every row has an unparseable timestamp, so
			// the mapper drops them all (batch is empty) but len==limit forces
			// a second round-trip.
			rows := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				rows = append(rows, map[string]interface{}{
					"id":             fmt.Sprintf("bad-%d", i),
					"activityAction": "View",
					"requestTime":    "not-a-timestamp",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": rows})
		case 1:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": "good-1", "activityAction": "Sign On", "requestTime": "2024-01-01T11:00:00Z", "userId": "user-1"},
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

	handlerCalls := 0
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			handlerCalls++
			if len(batch) == 0 {
				t.Errorf("handler invoked with an empty batch")
			}
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler calls = %d, want 1 (empty first page must be skipped)", handlerCalls)
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
