package tenable

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/audit-log/v1/events") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("X-ApiKeys"); !strings.Contains(got, "accessKey=") || !strings.Contains(got, "secretKey=") {
			t.Errorf("missing X-ApiKeys header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenableAuditPage{
			Events: []tenableEvent{
				{ID: "ev1", Action: "user.logged_in", CRUD: "u", Received: "2024-05-01T10:00:00.000Z", Actor: tenableEventActor{ID: "u1", Name: "alice@example.com"}},
				{ID: "ev2", Action: "user.password_changed", CRUD: "u", Received: "2024-05-01T11:00:00Z", IsFailure: true, Actor: tenableEventActor{ID: "u2", Name: "bob@example.com"}},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)},
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
	if collected[0].EventType != "user.logged_in" || collected[0].Outcome != "success" {
		t.Errorf("entry 0 = %+v", collected[0])
	}
	if collected[1].Outcome != "failure" {
		t.Errorf("entry 1 Outcome = %q; want failure", collected[1].Outcome)
	}
}

func TestFetchAccessAuditLogs_NotAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
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

// TestFetchAccessAuditLogs_NotAvailableOn404 verifies that an HTTP 404 from
// the audit-log endpoint (Tenable returns this when the endpoint is not
// enabled for the tenant's plan tier) is soft-skipped as
// access.ErrAuditNotAvailable rather than propagating as a hard sync failure
// — matching the 401/403 behaviour and every other audit connector in this
// package set. Before the fix isAuditNotAvailable only matched 401/403, so a
// 404 surfaced as a generic "status 404" error and failed the whole sync.
func TestFetchAccessAuditLogs_NotAvailableOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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

// TestFetchAccessAuditLogs_DrainsMultiplePages exercises the Tenable
// `sort=received_asc` + `date.gt` advancement loop. The previous
// single-shot implementation silently capped each sync at the 1000-
// event page limit; tenants with larger backlogs would lose events.
// We serve a full 1000-event page followed by a smaller page and
// assert (1) every event is delivered, (2) the second request
// advances `date.gt` past the page-1 max, and (3) the loop terminates
// on the partial page.
func TestFetchAccessAuditLogs_DrainsMultiplePages(t *testing.T) {
	const fullPage = 1000
	page1 := make([]tenableEvent, fullPage)
	base := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < fullPage; i++ {
		page1[i] = tenableEvent{
			ID:       fmt.Sprintf("p1-%d", i),
			Action:   "user.logged_in",
			Received: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			Actor:    tenableEventActor{ID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("user%d@example.com", i)},
		}
	}
	page1Max := base.Add(time.Duration(fullPage-1) * time.Second)
	page2 := []tenableEvent{
		{ID: "p2-0", Action: "user.password_changed", Received: page1Max.Add(time.Second).Format(time.RFC3339), Actor: tenableEventActor{ID: "u-late", Name: "late@example.com"}},
		{ID: "p2-1", Action: "user.logged_out", Received: page1Max.Add(2 * time.Second).Format(time.RFC3339), Actor: tenableEventActor{ID: "u-late2", Name: "late2@example.com"}},
	}
	var (
		calls       int
		seenFilters []string
		seenSort    string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		seenFilters = append(seenFilters, r.URL.Query().Get("f"))
		if got := r.URL.Query().Get("sort"); got != "" {
			seenSort = got
		}
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1:
			_ = json.NewEncoder(w).Encode(tenableAuditPage{Events: page1})
		case 2:
			_ = json.NewEncoder(w).Encode(tenableAuditPage{Events: page2})
		default:
			t.Errorf("unexpected request #%d", calls)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: base.Add(-time.Hour)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d; want 2 (full page + partial page)", calls)
	}
	if seenSort != "received_asc" {
		t.Errorf("sort = %q; want received_asc so the loop walks the queue forward", seenSort)
	}
	if got := len(collected); got != fullPage+len(page2) {
		t.Fatalf("collected %d entries; want %d", got, fullPage+len(page2))
	}
	if !strings.Contains(seenFilters[1], page1Max.UTC().Format("2006-01-02T15:04:05")) {
		t.Errorf("page-2 filter %q does not advance past page-1 max %s",
			seenFilters[1], page1Max.UTC().Format("2006-01-02T15:04:05"))
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

// TestFetchAccessAuditLogs_DropsUnparseableTimestamp verifies that an event
// whose `received` value is present but not a valid timestamp is dropped
// rather than emitted with a zero (0001-01-01) timestamp.
func TestFetchAccessAuditLogs_DropsUnparseableTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenableAuditPage{
			Events: []tenableEvent{
				{ID: "ev-good", Action: "user.logged_in", CRUD: "u", Received: "2024-05-01T10:00:00.000Z", Actor: tenableEventActor{ID: "u1"}},
				{ID: "ev-bad", Action: "user.logged_in", CRUD: "u", Received: "not-a-timestamp", Actor: tenableEventActor{ID: "u2"}},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if len(collected) != 1 {
		t.Fatalf("collected %d; want 1 (unparseable-timestamp event must be dropped): %#v", len(collected), collected)
	}
	if collected[0].EventID != "ev-good" {
		t.Errorf("kept entry = %+v, want ev-good", collected[0])
	}
	for _, e := range collected {
		if e.Timestamp.IsZero() {
			t.Errorf("emitted entry with zero timestamp: %+v", e)
		}
	}
}

// TestFetchAccessAuditLogs_StalledFullPageErrors verifies that a FULL page
// whose events do not advance the watermark surfaces an error instead of a
// false-complete drain. Tenable's only pagination lever is
// `date.gt:{received}`, so when more than pageLimit events share the same
// second (here a full page all stamped at the cursor), the cursor cannot
// advance — returning nil would persist an unchanged cursor and permanently
// stall the audit stream, silently dropping every later event. Before the fix
// the loop returned nil; now it must error so the sync is retried/alerted.
func TestFetchAccessAuditLogs_StalledFullPageErrors(t *testing.T) {
	const fullPage = 1000
	since := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)
	stuck := make([]tenableEvent, fullPage)
	for i := 0; i < fullPage; i++ {
		// Every event is stamped at exactly the cursor second, so none
		// is After(cursor) and the watermark never advances.
		stuck[i] = tenableEvent{
			ID:       fmt.Sprintf("stuck-%d", i),
			Action:   "user.logged_in",
			Received: since.Format(time.RFC3339),
			Actor:    tenableEventActor{ID: fmt.Sprintf("u%d", i)},
		}
	}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls > 2 {
			t.Errorf("connector kept requesting after a stalled page (call #%d) — possible infinite loop", calls)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenableAuditPage{Events: stuck})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: since},
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err == nil {
		t.Fatal("expected a stall error on a full page that cannot advance the cursor; got nil (silent audit gap)")
	}
	if !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("err = %v; want a 'stalled' pagination error", err)
	}
	if err == access.ErrAuditNotAvailable {
		t.Fatalf("err = ErrAuditNotAvailable; want a generic stall error")
	}
}
