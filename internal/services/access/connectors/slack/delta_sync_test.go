package slack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestSyncIdentitiesDelta_MapsLifecycleEvents(t *testing.T) {
	var mu sync.Mutex
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, "/audit/v1/logs") {
			t.Errorf("path = %s", r.URL.Path)
		}
		// Verify the lifecycle action filter is applied.
		gotActions := r.URL.Query().Get("action")
		if !strings.Contains(gotActions, "user_created") || !strings.Contains(gotActions, "user_deactivated") {
			t.Errorf("action filter = %q; want user lifecycle events", gotActions)
		}
		switch call {
		case 0:
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"entries": []map[string]interface{}{
					{
						"id":          "e-1",
						"date_create": 1704110400,
						"action":      "user_created",
						"actor":       map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "ADMIN1"}},
						"entity":      map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "U-NEW"}},
					},
					{
						"id":          "e-2",
						"date_create": 1704110500,
						"action":      "user_deactivated",
						"actor":       map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "ADMIN1"}},
						"entity":      map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "U-GONE"}},
					},
				},
				"response_metadata": map[string]interface{}{"next_cursor": "c2"},
			})
		case 1:
			if r.URL.Query().Get("cursor") != "c2" {
				t.Errorf("cursor = %s; want c2", r.URL.Query().Get("cursor"))
			}
			call++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"entries": []map[string]interface{}{
					{
						"id":          "e-3",
						"date_create": 1704114000,
						"action":      "user_role_admin_granted",
						"entity":      map[string]interface{}{"type": "user", "user": map[string]interface{}{"id": "U-PROMOTED"}},
					},
				},
				"response_metadata": map[string]interface{}{"next_cursor": ""},
			})
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var allBatch []*access.Identity
	var allRemoved []string
	finalLink, err := c.SyncIdentitiesDelta(context.Background(), nil, validSecrets(), "1704000000",
		func(batch []*access.Identity, removed []string, _ string) error {
			allBatch = append(allBatch, batch...)
			allRemoved = append(allRemoved, removed...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(allBatch) != 2 {
		t.Fatalf("batch = %d; want 2 (U-NEW + U-PROMOTED)", len(allBatch))
	}
	if len(allRemoved) != 1 || allRemoved[0] != "U-GONE" {
		t.Errorf("removed = %v; want [U-GONE]", allRemoved)
	}
	// Cursor should advance to the newest event's unix-seconds (e-3 at 1704114000).
	if finalLink != "1704114000" {
		t.Errorf("finalLink = %q; want 1704114000", finalLink)
	}
}

func TestSyncIdentitiesDelta_NotEnterpriseReturnsTokenExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "team_not_eligible"})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), nil, validSecrets(), "",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestSyncIdentitiesDelta_PreservesCursorWhenNoNewEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":                true,
			"entries":           []map[string]interface{}{},
			"response_metadata": map[string]interface{}{"next_cursor": ""},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	finalLink, err := c.SyncIdentitiesDelta(context.Background(), nil, validSecrets(), "1704000000",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if finalLink != "1704000000" {
		t.Errorf("finalLink = %q; want 1704000000 (echo original cursor when no events)", finalLink)
	}
}

// A workspace whose audit API always returns a non-empty next_cursor must
// not loop forever: slackAuditMaxPages bounds the request count and the
// delta sync returns the latest cursor so the next run resumes.
func TestSyncIdentitiesDelta_MaxPagesGuard(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":                true,
			"entries":           []map[string]interface{}{},
			"response_metadata": map[string]interface{}{"next_cursor": "always-more"},
		})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), nil, validSecrets(), "1704000000",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != slackAuditMaxPages {
		t.Errorf("calls = %d; want %d (bounded by guard)", calls, slackAuditMaxPages)
	}
}

func TestSyncIdentitiesDelta_SatisfiesInterface(t *testing.T) {
	var _ access.IdentityDeltaSyncer = New()
}

func TestSlack_InitialDeltaCursor_UnixSecondsParseable(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	secs, perr := strconv.ParseInt(cursor, 10, 64)
	if perr != nil {
		t.Fatalf("seeded cursor %q is not a Unix-seconds integer: %v", cursor, perr)
	}
	if delta := time.Since(time.Unix(secs, 0)); delta > 5*time.Second || delta < -5*time.Second {
		t.Errorf("seeded cursor %q is %v away from now; want within 5s", cursor, delta)
	}
}
