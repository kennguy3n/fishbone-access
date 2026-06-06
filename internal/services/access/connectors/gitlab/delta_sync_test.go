package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestGitlab_SyncIdentitiesDelta_MapsLifecycleEvents(t *testing.T) {
	var mu sync.Mutex
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, "/api/v4/groups/12345/audit_events") {
			t.Errorf("path = %s", r.URL.Path)
		}
		switch call {
		case 0:
			call++
			w.Header().Set("X-Next-Page", "2")
			payload := []map[string]interface{}{
				{
					"id":          int64(1),
					"author_id":   int64(99),
					"entity_id":   int64(12345),
					"entity_type": "Group",
					"created_at":  "2024-01-01T10:00:00.123Z",
					"details": map[string]interface{}{
						"event_name":     "user_add_to_group",
						"target_id":      int64(1001),
						"target_details": "alice",
					},
				},
				{
					"id":          int64(2),
					"author_id":   int64(99),
					"entity_id":   int64(12345),
					"entity_type": "Group",
					"created_at":  "2024-01-01T10:00:05.456Z",
					"details": map[string]interface{}{
						"event_name":     "user_remove_from_group",
						"target_id":      int64(1002),
						"target_details": "bob",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
		case 1:
			if r.URL.Query().Get("page") != "2" {
				t.Errorf("page = %s; want 2", r.URL.Query().Get("page"))
			}
			call++
			w.Header().Set("X-Next-Page", "")
			payload := []map[string]interface{}{
				{
					"id":          int64(3),
					"author_id":   int64(99),
					"entity_id":   int64(12345),
					"entity_type": "Group",
					"created_at":  "2024-01-01T10:00:10.789Z",
					"details": map[string]interface{}{
						"event_name":     "user_access_change",
						"target_id":      int64(1003),
						"target_details": "carol",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var allBatch []*access.Identity
	var allRemoved []string
	finalLink, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2024-01-01T09:00:00Z",
		func(batch []*access.Identity, removed []string, _ string) error {
			allBatch = append(allBatch, batch...)
			allRemoved = append(allRemoved, removed...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(allBatch) != 2 || allBatch[0].ExternalID != "1001" || allBatch[1].ExternalID != "1003" {
		t.Errorf("batch = %v; want [1001, 1003]", batchIDs(allBatch))
	}
	if len(allRemoved) != 1 || allRemoved[0] != "1002" {
		t.Errorf("removed = %v; want [1002]", allRemoved)
	}
	// Cursor should advance to the newest event's timestamp (e-3 at 10:00:10.789Z).
	wantTS, _ := time.Parse(time.RFC3339Nano, "2024-01-01T10:00:10.789Z")
	gotTS, _ := time.Parse(time.RFC3339Nano, finalLink)
	if !gotTS.Equal(wantTS) {
		t.Errorf("finalLink = %q; want timestamp equal to 2024-01-01T10:00:10.789Z", finalLink)
	}
}

func TestGitlab_SyncIdentitiesDelta_ForbiddenReturnsTokenExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Fatalf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestGitlab_SyncIdentitiesDelta_PreservesCursorWhenNoNewEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Next-Page", "")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	finalLink, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2024-01-01T09:00:00Z",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if finalLink != "2024-01-01T09:00:00Z" {
		t.Errorf("finalLink = %q; want echo of original cursor when no events", finalLink)
	}
}

func TestGitlab_SyncIdentitiesDelta_NonLifecycleEventsSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Next-Page", "")
		payload := []map[string]interface{}{
			{
				"id":          int64(99),
				"author_id":   int64(50),
				"entity_id":   int64(12345),
				"entity_type": "Group",
				"created_at":  "2024-01-01T10:00:00Z",
				"details": map[string]interface{}{
					"event_name": "project_archived",
					"target_id":  int64(7777),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var batchCount, removedCount int
	if _, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "",
		func(batch []*access.Identity, removed []string, _ string) error {
			batchCount += len(batch)
			removedCount += len(removed)
			return nil
		}); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if batchCount != 0 || removedCount != 0 {
		t.Errorf("batch=%d removed=%d; want both 0 (non-lifecycle event)", batchCount, removedCount)
	}
}

func TestGitlab_SyncIdentitiesDelta_SatisfiesInterface(t *testing.T) {
	var _ access.IdentityDeltaSyncer = New()
}

func TestGitlab_InitialDeltaCursor_RoundTripsThroughSyncIdentitiesDelta(t *testing.T) {
	// Pin the contract: InitialDeltaCursor's output must be a
	// shape SyncIdentitiesDelta accepts without panicking. The
	// gitlab path round-trips RFC3339Nano through parseGitlabTime,
	// so feeding the seed back as deltaLink must NOT trigger the
	// "since == zero" fallback (i.e. parseGitlabTime returns
	// non-zero) and must NOT crash on http.NewRequest.
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	parsed := parseGitlabTime(cursor)
	if parsed.IsZero() {
		t.Fatalf("seeded cursor %q failed parseGitlabTime round-trip", cursor)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded cursor %q is more than 5s in the past", cursor)
	}
}

func batchIDs(ids []*access.Identity) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.ExternalID)
	}
	return out
}
