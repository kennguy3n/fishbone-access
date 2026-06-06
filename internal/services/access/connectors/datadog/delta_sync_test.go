package datadog

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

func datadogDeltaConfig() map[string]interface{} { return map[string]interface{}{} }
func datadogDeltaSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "k", "application_key": "ak"}
}

func TestDatadog_SyncIdentitiesDelta_HappyPath_TwoPages(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method=%q; want GET", r.Method)
		}
		hits++
		// First call uses the constructed audit-events query; the
		// second call follows links.next which only carries the
		// cursor — so filter[query] is only asserted on hit 1.
		if hits == 1 && r.URL.Query().Get("filter[query]") == "" {
			t.Errorf("filter[query] missing on first call")
		}
		switch hits {
		case 1:
			resp := map[string]interface{}{
				"data": []map[string]interface{}{{
					"id": "ev-1",
					"attributes": map[string]interface{}{
						"timestamp": time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339),
						"attributes": map[string]interface{}{
							"usr.id":    "u-1",
							"usr.email": "alice@example.com",
							"usr.name":  "Alice",
							"evt.name":  "User created",
						},
					},
				}},
				"links": map[string]interface{}{"next": "https://api.datadoghq.com/api/v2/audit/events?page%5Bcursor%5D=tok2"},
			}
			b, _ := json.Marshal(resp)
			_, _ = w.Write(b)
		case 2:
			resp := map[string]interface{}{
				"data": []map[string]interface{}{{
					"id": "ev-2",
					"attributes": map[string]interface{}{
						"timestamp": time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339),
						"attributes": map[string]interface{}{
							"usr.id":   "u-2",
							"evt.name": "User disabled",
						},
					},
				}},
				"links": map[string]interface{}{},
			}
			b, _ := json.Marshal(resp)
			_, _ = w.Write(b)
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL

	var (
		gotBatch   []*access.Identity
		gotRemoved []string
	)
	final, err := c.SyncIdentitiesDelta(context.Background(), datadogDeltaConfig(), datadogDeltaSecrets(), "",
		func(batch []*access.Identity, removed []string, _ string) error {
			gotBatch = append(gotBatch, batch...)
			gotRemoved = append(gotRemoved, removed...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if final == "" {
		t.Errorf("final cursor empty; want a timestamp")
	}
	if len(gotBatch) != 1 {
		t.Errorf("got %d active identities; want 1", len(gotBatch))
	}
	if len(gotRemoved) != 1 || gotRemoved[0] != "u-2" {
		t.Errorf("removed=%v; want [u-2]", gotRemoved)
	}
	if hits != 2 {
		t.Errorf("hits=%d; want 2 pages", hits)
	}
}

func TestDatadog_SyncIdentitiesDelta_ExpiredCursor_ReturnsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("upstream should not be called when cursor is locally detected as expired")
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL

	old := time.Now().UTC().Add(-90 * 24 * time.Hour).Format(time.RFC3339)
	_, err := c.SyncIdentitiesDelta(context.Background(), datadogDeltaConfig(), datadogDeltaSecrets(), old,
		func([]*access.Identity, []string, string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("err=%v; want ErrDeltaTokenExpired", err)
	}
}

func TestDatadog_SyncIdentitiesDelta_BackendCursorExpired_ReturnsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["filter[from] is out of range, beyond retention window"]}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL

	cursor := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	_, err := c.SyncIdentitiesDelta(context.Background(), datadogDeltaConfig(), datadogDeltaSecrets(), cursor,
		func([]*access.Identity, []string, string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("err=%v; want ErrDeltaTokenExpired", err)
	}
}

func TestDatadog_SyncIdentitiesDelta_InvalidCursor_Rejected(t *testing.T) {
	c := New()
	_, err := c.SyncIdentitiesDelta(context.Background(), datadogDeltaConfig(), datadogDeltaSecrets(), "not-a-timestamp",
		func([]*access.Identity, []string, string) error { return nil })
	if err == nil {
		t.Fatal("err=nil; want error for malformed cursor")
	}
	if !strings.Contains(err.Error(), "invalid deltaLink") {
		t.Errorf("err=%v; want 'invalid deltaLink' message", err)
	}
}

// TestDatadog_SyncIdentitiesDelta_ConsistentWindow pins the query
// window on a first run. Both filter[from] and filter[to] are now
// derived from a single time.Now() snapshot, so the bounds are
// internally consistent: from is exactly one hour before to, and from
// is never after to. Reading the clock twice (once per bound) made the
// window non-deterministic and could leave a sliver of time covered by
// neither the current nor the next poll.
func TestDatadog_SyncIdentitiesDelta_ConsistentWindow(t *testing.T) {
	var gotFrom, gotTo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFrom = r.URL.Query().Get("filter[from]")
		gotTo = r.URL.Query().Get("filter[to]")
		_, _ = w.Write([]byte(`{"data":[],"links":{}}`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL

	if _, err := c.SyncIdentitiesDelta(context.Background(), datadogDeltaConfig(), datadogDeltaSecrets(), "",
		func([]*access.Identity, []string, string) error { return nil }); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	from, err := time.Parse(time.RFC3339, gotFrom)
	if err != nil {
		t.Fatalf("parse filter[from] %q: %v", gotFrom, err)
	}
	to, err := time.Parse(time.RFC3339, gotTo)
	if err != nil {
		t.Fatalf("parse filter[to] %q: %v", gotTo, err)
	}
	if to.Before(from) {
		t.Fatalf("filter[to] %s is before filter[from] %s", gotTo, gotFrom)
	}
	if d := to.Sub(from); d != time.Hour {
		t.Fatalf("first-run window = %s, want exactly 1h (from and to must share one clock snapshot)", d)
	}
}

func TestDatadog_SatisfiesIdentityDeltaSyncerInterface(_ *testing.T) {
	var _ access.IdentityDeltaSyncer = (*DatadogAccessConnector)(nil)
}

func TestDatadog_InitialDeltaCursor_RoundTripsThroughSyncIdentitiesDelta(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	// SyncIdentitiesDelta parses cursors via time.Parse(time.RFC3339);
	// the seed must satisfy that exact contract.
	parsed, perr := time.Parse(time.RFC3339, cursor)
	if perr != nil {
		t.Fatalf("seeded cursor %q failed RFC3339 parse: %v", cursor, perr)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded cursor %q is more than 5s in the past", cursor)
	}
}
