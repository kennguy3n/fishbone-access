package jira

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

func deltaConfig() map[string]interface{} {
	cfg := validConfig()
	cfg["org_id"] = "org-abc-123"
	return cfg
}

func TestJira_SyncIdentitiesDelta_HappyPath(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.Contains(r.URL.Path, "/admin/v1/orgs/org-abc-123/events") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":   "evt-1",
					"type": "USER_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:00:00Z",
						"action": "user_created",
						"actor":  map[string]interface{}{"id": "admin", "email": "admin@x.com"},
						"context": []map[string]interface{}{
							{"id": "u-new", "type": "USER", "attributes": map[string]interface{}{"email": "new@x.com"}},
						},
					},
				},
				{
					"id":   "evt-2",
					"type": "USER_DEACTIVATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:05:00Z",
						"action": "user_deactivated",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{"id": "u-gone", "type": "USER"},
						},
					},
				},
				{
					"id":   "evt-3",
					"type": "USER_DELETED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:10:00Z",
						"action": "user_deleted",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{"id": "u-dead", "type": "USER"},
						},
					},
				},
				{
					"id":   "evt-4-ignored",
					"type": "PROJECT_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:15:00Z",
						"action": "project_created",
						"actor":  map[string]interface{}{"id": "admin"},
					},
				},
			},
			"links": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	var (
		batchedIdentities []*access.Identity
		batchedRemoved    []string
	)
	cursor, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:59:00Z",
		func(batch []*access.Identity, removed []string, _ string) error {
			batchedIdentities = append(batchedIdentities, batch...)
			batchedRemoved = append(batchedRemoved, removed...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d; want 1", calls)
	}
	if len(batchedIdentities) != 2 || batchedIdentities[0].ExternalID != "u-new" || batchedIdentities[1].ExternalID != "u-gone" {
		t.Errorf("identities = %+v", batchedIdentities)
	}
	if batchedIdentities[0].Status != "active" || batchedIdentities[1].Status != "inactive" {
		t.Errorf("status = %q / %q; want active / inactive",
			batchedIdentities[0].Status, batchedIdentities[1].Status)
	}
	if len(batchedRemoved) != 1 || batchedRemoved[0] != "u-dead" {
		t.Errorf("removed = %v; want [u-dead]", batchedRemoved)
	}
	// The cursor advances for ALL events on the page (including
	// the non-lifecycle PROJECT_CREATED at 12:15:00), not just the
	// user-lifecycle ones we surface. This prevents the cursor from
	// pinning behind a flood of unrelated events on busy orgs.
	if !strings.HasPrefix(cursor, "2025-05-10T12:15:00") {
		t.Errorf("cursor = %q; want newest seen across all events (evt-4 PROJECT_CREATED)", cursor)
	}
}

func TestJira_SyncIdentitiesDelta_ExpiredCursor(t *testing.T) {
	c := New()
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "not-a-timestamp", nil)
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Errorf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestJira_SyncIdentitiesDelta_404TriggersTokenExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:59:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Errorf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestJira_SyncIdentitiesDelta_MissingOrgIDRejected(t *testing.T) {
	c := New()
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "org_id is required") {
		t.Errorf("err = %v", err)
	}
}

func TestJira_SyncIdentitiesDelta_500Propagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:59:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want 500 error", err)
	}
}

func TestJira_SyncIdentitiesDelta_NoEventsKeepsCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":  []map[string]interface{}{},
			"links": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cursor, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(cursor, "2025-05-10T11:00:00") {
		t.Errorf("cursor = %q; want supplied since (no events)", cursor)
	}
}

func TestJira_SyncIdentitiesDelta_DefaultsToOneHourLookback(t *testing.T) {
	captured := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.Query().Get("from")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{}, "links": map[string]interface{}{}})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	ts, parseErr := time.Parse(time.RFC3339, captured)
	if parseErr != nil {
		t.Fatalf("from query param not RFC3339: %q (%v)", captured, parseErr)
	}
	if dt := time.Since(ts); dt < 30*time.Minute || dt > 2*time.Hour {
		t.Errorf("from = %v; want ~1 hour ago", ts)
	}
}

func TestJira_SyncIdentitiesDelta_DestructiveEventWithoutUSERContextDropped(t *testing.T) {
	// A user_deleted event missing its USER context entry must NOT
	// fall back to actor.id — doing so would tombstone the admin's
	// identity instead of the deleted user. Better to drop the
	// event entirely and let the next full sync reconcile the
	// missing user record than to silently corrupt the admin's
	// identity.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":   "evt-bad-delete",
					"type": "USER_DELETED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:00:00Z",
						"action": "user_deleted",
						"actor":  map[string]interface{}{"id": "admin", "email": "admin@x.com"},
						// no USER context entry — Atlassian shouldn't
						// emit this in practice, but we refuse to
						// guess the target.
					},
				},
			},
			"links": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var (
		batch   []*access.Identity
		removed []string
	)
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(b []*access.Identity, r []string, _ string) error {
			batch = append(batch, b...)
			removed = append(removed, r...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %v; want empty (destructive event without USER context must be dropped, NOT misattributed to actor 'admin')", removed)
	}
	if len(batch) != 0 {
		t.Errorf("batch = %+v; want empty", batch)
	}
}

func TestJira_SyncIdentitiesDelta_EventWithoutUSERContextDroppedRegardlessOfAction(t *testing.T) {
	// EVERY user-lifecycle event without a USER context entry is
	// dropped — no actor fallback for any action. The actor is the
	// API caller (typically the admin who performed the action),
	// NOT the target user. Falling back to actor for non-destructive
	// events would still mis-attribute lifecycle status to the
	// admin's identity record. The architecturally correct fix is
	// to refuse to guess and let the next full sync reconcile any
	// dropped events idempotently. This matches gitlab/aws/slack
	// delta-sync behavior.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					// Non-destructive but admin-initiated: would
					// have previously been mis-attributed to the
					// actor (admin) and marked active in the actor's
					// identity record.
					"id":   "evt-invited",
					"type": "USER_INVITED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:00:00Z",
						"action": "user_invited",
						"actor":  map[string]interface{}{"id": "admin1", "email": "admin@x.com"},
					},
				},
				{
					// user_deactivated: actor is admin, target is
					// the deactivated user. Previously this would
					// have marked the admin "inactive" via fallback.
					"id":   "evt-deactivated",
					"type": "USER_DEACTIVATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:01:00Z",
						"action": "user_deactivated",
						"actor":  map[string]interface{}{"id": "admin2", "email": "admin@x.com"},
					},
				},
				{
					// Self-service: even here we drop, because the
					// only safe way to confirm "actor IS target"
					// is via the USER context entry.
					"id":   "evt-self-accept",
					"type": "USER_INVITATION_ACCEPTED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:02:00Z",
						"action": "user_invitation_accepted",
						"actor":  map[string]interface{}{"id": "u-self", "email": "self@x.com"},
					},
				},
			},
			"links": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var (
		batch   []*access.Identity
		removed []string
	)
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(b []*access.Identity, r []string, _ string) error {
			batch = append(batch, b...)
			removed = append(removed, r...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(batch) != 0 {
		t.Errorf("batch = %+v; want empty (every event without USER context must be dropped)", batch)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %v; want empty", removed)
	}
}

func TestJira_SyncIdentitiesDelta_CursorAdvancesOnNonLifecycleEvents(t *testing.T) {
	// A page with only non-lifecycle events should still advance
	// the cursor — otherwise long stretches of project / settings
	// activity would pin the cursor and force the next sync to
	// re-fetch the same pages.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":   "evt-proj",
					"type": "PROJECT_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:45:00Z",
						"action": "project_created",
						"actor":  map[string]interface{}{"id": "admin"},
					},
				},
			},
			"links": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cursor, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(cursor, "2025-05-10T12:45:00") {
		t.Errorf("cursor = %q; want 2025-05-10T12:45:00 (cursor must advance on non-lifecycle events too)", cursor)
	}
}

func TestJira_SyncIdentitiesDelta_DisplayNamePopulatedFromContext(t *testing.T) {
	// Atlassian Admin event payloads surface the target user's
	// display name in the USER context entry's attributes
	// (either "displayName" or "name"). The mapper must extract
	// it so delta-discovered identities carry the same
	// DisplayName field that full-sync-discovered ones do —
	// otherwise the UI / audit pipeline shows a blank name
	// between a delta and the next full sync.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":   "evt-modern",
					"type": "USER_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:00:00Z",
						"action": "user_created",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{
								"id":   "u-modern",
								"type": "USER",
								"attributes": map[string]interface{}{
									"email":       "modern@x.com",
									"displayName": "Modern User",
								},
							},
						},
					},
				},
				{
					"id":   "evt-legacy",
					"type": "USER_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:01:00Z",
						"action": "user_created",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{
								"id":   "u-legacy",
								"type": "USER",
								"attributes": map[string]interface{}{
									"email": "legacy@x.com",
									"name":  "Legacy User",
								},
							},
						},
					},
				},
				{
					"id":   "evt-blank",
					"type": "USER_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:02:00Z",
						"action": "user_created",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{
								"id":   "u-blank",
								"type": "USER",
								"attributes": map[string]interface{}{
									"email": "blank@x.com",
								},
							},
						},
					},
				},
			},
			"links": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var batch []*access.Identity
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(b []*access.Identity, _ []string, _ string) error {
			batch = append(batch, b...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(batch) != 3 {
		t.Fatalf("batch = %d; want 3", len(batch))
	}
	if batch[0].ExternalID != "u-modern" || batch[0].DisplayName != "Modern User" {
		t.Errorf("modern: got %+v; want DisplayName=%q", batch[0], "Modern User")
	}
	if batch[1].ExternalID != "u-legacy" || batch[1].DisplayName != "Legacy User" {
		t.Errorf("legacy: got %+v; want DisplayName=%q (name fallback)", batch[1], "Legacy User")
	}
	if batch[2].ExternalID != "u-blank" || batch[2].DisplayName != "" {
		t.Errorf("blank: got %+v; want empty DisplayName (no source field)", batch[2])
	}
}

func TestJira_SyncIdentitiesDelta_AccountTypeFromContextSetsServiceAccount(t *testing.T) {
	// When the USER context entry includes accountType=app the
	// mapped Identity must be IdentityTypeServiceAccount so that
	// downstream reconcilers and the leaver flow treat the entity
	// as a service account between the delta and the next full
	// sync. Default (absent / "atlassian") stays IdentityTypeUser.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":   "evt-svc",
					"type": "USER_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:00:00Z",
						"action": "user_created",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{
								"id":   "svc-bot",
								"type": "USER",
								"attributes": map[string]interface{}{
									"email":       "bot@x.com",
									"displayName": "BotAcct",
									"accountType": "app",
								},
							},
						},
					},
				},
				{
					"id":   "evt-human",
					"type": "USER_CREATED",
					"attributes": map[string]interface{}{
						"time":   "2025-05-10T12:01:00Z",
						"action": "user_created",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{
								"id":   "u-human",
								"type": "USER",
								"attributes": map[string]interface{}{
									"email":       "human@x.com",
									"displayName": "Human User",
									"accountType": "atlassian",
								},
							},
						},
					},
				},
			},
			"links": map[string]interface{}{},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var batch []*access.Identity
	_, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(b []*access.Identity, _ []string, _ string) error {
			batch = append(batch, b...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("batch = %d; want 2", len(batch))
	}
	if batch[0].ExternalID != "svc-bot" || batch[0].Type != access.IdentityTypeServiceAccount {
		t.Errorf("svc-bot: got %+v; want Type=ServiceAccount", batch[0])
	}
	if batch[1].ExternalID != "u-human" || batch[1].Type != access.IdentityTypeUser {
		t.Errorf("u-human: got %+v; want Type=User", batch[1])
	}
}

// TestJira_SyncIdentitiesDelta_CursorPreservesSubSecondPrecision
// codifies the cross-connector cursor-precision contract:
//
//   - The persisted cursor returned by SyncIdentitiesDelta MUST be
//     formatted as RFC3339Nano so sub-second precision round-trips
//     through save/load. gitlab/delta_sync.go:109 and bamboohr's
//     delta cursor both use nano precision; truncating to second
//     precision here would cause sub-second events to re-deliver
//     on every subsequent sync (correct under the at-least-once
//     contract, but wasteful).
//   - The wire `from=` filter still uses RFC3339 second-precision
//     because Atlassian's endpoint only honors that granularity —
//     that's a property of the upstream API, not the cursor format.
func TestJira_SyncIdentitiesDelta_CursorPreservesSubSecondPrecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"id":   "evt-nano",
					"type": "audit-event",
					"attributes": map[string]interface{}{
						"action": "user_created",
						"time":   "2025-05-10T12:15:00.123456789Z",
						"actor":  map[string]interface{}{"id": "admin"},
						"context": []map[string]interface{}{
							{
								"type":       "USER",
								"id":         "u1",
								"attributes": map[string]interface{}{"email": "u1@example.com"},
							},
						},
					},
				},
			},
		})
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cursor, err := c.SyncIdentitiesDelta(context.Background(), deltaConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// The persisted cursor MUST round-trip through RFC3339Nano
	// with sub-second precision preserved. Parsing as
	// time.RFC3339Nano must succeed AND the parsed value must
	// match the source nanosecond.
	parsed, perr := time.Parse(time.RFC3339Nano, cursor)
	if perr != nil {
		t.Fatalf("cursor %q is not RFC3339Nano: %v", cursor, perr)
	}
	if parsed.Nanosecond() != 123456789 {
		t.Errorf("cursor nanoseconds = %d; want 123456789 (sub-second precision must round-trip)", parsed.Nanosecond())
	}
}

func TestJira_SatisfiesIdentityDeltaSyncerInterface(t *testing.T) {
	var _ access.IdentityDeltaSyncer = New()
}

func TestJira_InitialDeltaCursor_RoundTripsThroughSyncIdentitiesDelta(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	parsed := parseJiraTime(cursor)
	if parsed.IsZero() {
		t.Fatalf("seeded cursor %q failed parseJiraTime round-trip", cursor)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded cursor %q is more than 5s in the past", cursor)
	}
}
