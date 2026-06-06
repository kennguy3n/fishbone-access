package onepassword

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestFetchAccessAuditLogs_PaginatesAndMaps(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/signinattempts" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("missing bearer auth: %q", got)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(onepasswordSigninPage{
				Cursor:  "next-1",
				HasMore: true,
				Items: []onepasswordSigninAttempt{
					{UUID: "ev1", Category: "success", Type: "credentials_ok", Timestamp: "2024-08-01T08:00:00.000Z", TargetUser: onepasswordSigninUser{UUID: "u1", Email: "alice@example.com"}, Client: onepasswordSigninClient{IPAddress: "10.0.0.1"}},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(onepasswordSigninPage{
			HasMore: false,
			Items: []onepasswordSigninAttempt{
				{UUID: "ev2", Category: "credentials_failed", Type: "wrong_password", Timestamp: "2024-08-01T09:00:00Z", TargetUser: onepasswordSigninUser{UUID: "u2", Email: "bob@example.com"}},
			},
		})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	var collected []*access.AuditLogEntry
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{access.DefaultAuditPartition: time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)},
		func(batch []*access.AuditLogEntry, _ time.Time, _ string) error {
			collected = append(collected, batch...)
			return nil
		})
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d; want 2", calls)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d; want 2", len(collected))
	}
	if collected[0].ActorEmail != "alice@example.com" || collected[0].Outcome != "success" {
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

// TestFetchAccessAuditLogs_UsesEventsAPIBaseURL guards against the
// Events Reporting API request being sent to the SCIM bridge. 1Password
// serves SCIM at scim.1password.com and audit/sign-in events at
// events.1password.com — different hosts and different services — so
// hitting `/api/v1/signinattempts` against the SCIM bridge 404s every
// page in production. This test wires distinct mock servers for the
// two services without `urlOverride` and asserts the Events request
// lands at the Events host and never touches SCIM.
func TestFetchAccessAuditLogs_UsesEventsAPIBaseURL(t *testing.T) {
	var (
		scimHits   int
		eventsHits int
	)
	scim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scimHits++
		t.Errorf("SCIM bridge received an audit request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(scim.Close)
	events := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eventsHits++
		if r.URL.Path != "/api/v1/signinattempts" {
			t.Errorf("events server got unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(onepasswordSigninPage{HasMore: false})
	}))
	t.Cleanup(events.Close)

	c := New()
	// Deliberately leave urlOverride empty so eventsBaseURL falls
	// through to cfg.EventsAPIURL and baseURL falls through to
	// cfg.AccountURL. This proves the two are wired to different
	// hosts in production.
	c.httpClient = func() httpDoer {
		return &http.Client{Transport: &http.Transport{}}
	}
	cfg := map[string]interface{}{
		"account_url":    scim.URL,
		"events_api_url": events.URL,
	}
	err := c.FetchAccessAuditLogs(context.Background(), cfg, validSecrets(), nil,
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if eventsHits == 0 {
		t.Fatalf("events server received 0 requests; want >=1")
	}
	if scimHits != 0 {
		t.Fatalf("SCIM bridge received %d audit requests; want 0", scimHits)
	}
}

func TestFetchAccessAuditLogs_FirstRunBackfillsRetentionWindow(t *testing.T) {
	// On the first run (zero since) the connector must request the full
	// backfill window, not the previous 24h, otherwise older sign-in history
	// is permanently lost. The 1Password Events API requires an explicit
	// start_time (it can't be omitted like Okta), so we assert the window
	// matches onepasswordAuditBackfill.
	var gotStart string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if s, ok := body["start_time"].(string); ok {
			gotStart = s
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(onepasswordSigninPage{HasMore: false})
	}))
	t.Cleanup(server.Close)

	c := New()
	c.urlOverride = server.URL
	c.httpClient = func() httpDoer { return server.Client() }

	before := time.Now()
	err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
		map[string]time.Time{}, // no cursor persisted -> zero since
		func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
	if err != nil {
		t.Fatalf("FetchAccessAuditLogs: %v", err)
	}
	if gotStart == "" {
		t.Fatal("server never received a start_time on the first-run reset request")
	}
	start, perr := time.Parse(time.RFC3339Nano, gotStart)
	if perr != nil {
		t.Fatalf("parse start_time %q: %v", gotStart, perr)
	}
	lookback := before.Sub(start)
	// Allow a small slack for the time elapsed between computing the window
	// and the assertion. Must be far larger than the old 24h default.
	if lookback < onepasswordAuditBackfill-time.Minute || lookback > onepasswordAuditBackfill+time.Minute {
		t.Errorf("first-run look-back = %s; want ~%s (90d backfill)", lookback, onepasswordAuditBackfill)
	}
}

func TestMapOnePasswordSigninAttempt_SkipsEmptyUUID(t *testing.T) {
	// Valid timestamp but empty UUID must be skipped: EventID would be empty
	// and break the dedup pipeline.
	if e := mapOnePasswordSigninAttempt(&onepasswordSigninAttempt{Timestamp: "2026-01-02T15:04:05Z"}); e != nil {
		t.Fatalf("expected nil for empty UUID, got %+v", e)
	}
	// With a UUID it should map.
	e := mapOnePasswordSigninAttempt(&onepasswordSigninAttempt{UUID: "u1", Timestamp: "2026-01-02T15:04:05Z"})
	if e == nil || e.EventID != "u1" {
		t.Fatalf("expected EventID=u1, got %+v", e)
	}
}
