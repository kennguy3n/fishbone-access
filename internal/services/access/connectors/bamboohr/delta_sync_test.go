package bamboohr

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

func newBambooHRTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *BambooHRAccessConnector) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return srv, c
}

// bambooDeltaTestRouter is a minimal router for delta tests. It
// serves the /v1/employees/changed page and per-id enrichment
// lookups (/v1/employees/{id}) from in-memory maps. Tests can
// override individual handlers if they need to simulate failures.
type bambooDeltaTestRouter struct {
	t              *testing.T
	changed        map[string]bambooChangedTestEmployee
	enrichment     map[string]bambooEmployee
	enrichmentFail map[string]int // employeeID -> status code
}

type bambooChangedTestEmployee struct {
	Action      string
	LastChanged string
}

func (r *bambooDeltaTestRouter) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.Contains(req.URL.Path, "/v1/employees/changed"):
			out := map[string]map[string]interface{}{}
			for id, change := range r.changed {
				out[id] = map[string]interface{}{
					"id":          id,
					"action":      change.Action,
					"lastChanged": change.LastChanged,
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"employees": out})
		case strings.HasPrefix(req.URL.Path, "/v1/employees/") &&
			req.URL.Path != "/v1/employees/directory" &&
			req.URL.Path != "/v1/employees/changed":
			id := strings.TrimPrefix(req.URL.Path, "/v1/employees/")
			if code, ok := r.enrichmentFail[id]; ok {
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`failure`))
				return
			}
			emp, ok := r.enrichment[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(emp)
		default:
			r.t.Errorf("unexpected path: %q", req.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func TestBambooHR_SyncIdentitiesDelta_HappyPath(t *testing.T) {
	router := &bambooDeltaTestRouter{
		t: t,
		changed: map[string]bambooChangedTestEmployee{
			"12345": {Action: "Inserted", LastChanged: "2025-05-10T12:00:00Z"},
			"12346": {Action: "Updated", LastChanged: "2025-05-10T12:05:00Z"},
			"12347": {Action: "Deleted", LastChanged: "2025-05-10T12:10:00Z"},
			"12348": {Action: "Unknown", LastChanged: "2025-05-10T12:15:00Z"},
		},
		enrichment: map[string]bambooEmployee{
			"12345": {ID: "12345", DisplayName: "Alice Asana", WorkEmail: "alice@example.com", JobTitle: "Engineer", Status: "Active"},
			"12346": {ID: "12346", FirstName: "Bob", LastName: "Builder", WorkEmail: "bob@example.com", JobTitle: "PM", Status: "Active"},
		},
	}
	_, c := newBambooHRTestServer(t, router.handler())

	var (
		ids     []*access.Identity
		removed []string
	)
	cursor, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(batch []*access.Identity, r []string, _ string) error {
			ids = append(ids, batch...)
			removed = append(removed, r...)
			return nil
		})
	if err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("identities = %d; want 2 (Inserted+Updated)", len(ids))
	}
	byID := map[string]*access.Identity{}
	for _, id := range ids {
		byID[id.ExternalID] = id
		if id.Status != "active" {
			t.Errorf("id %s status = %q; want active (delta should normalise like full-sync)", id.ExternalID, id.Status)
		}
	}
	if byID["12345"] == nil || byID["12345"].DisplayName != "Alice Asana" {
		t.Errorf("12345 display = %q; want Alice Asana (enrichment must populate)", byID["12345"].DisplayName)
	}
	if byID["12345"].Email != "alice@example.com" {
		t.Errorf("12345 email = %q; want alice@example.com", byID["12345"].Email)
	}
	if byID["12346"] == nil || byID["12346"].DisplayName != "Bob Builder" {
		t.Errorf("12346 display = %q; want Bob Builder (firstName+lastName fallback)", byID["12346"].DisplayName)
	}
	if len(removed) != 1 || removed[0] != "12347" {
		t.Errorf("removed = %v; want [12347]", removed)
	}
	gotCursor, perr := time.Parse(time.RFC3339Nano, cursor)
	if perr != nil {
		t.Fatalf("cursor not RFC3339Nano: %q (%v)", cursor, perr)
	}
	wantCursor := time.Date(2025, 5, 10, 12, 15, 0, 1, time.UTC)
	if !gotCursor.Equal(wantCursor) {
		t.Errorf("cursor = %s; want %s (max(lastChanged)+1ns across full page incl. Unknown)", gotCursor.Format(time.RFC3339Nano), wantCursor.Format(time.RFC3339Nano))
	}
}

func TestBambooHR_SyncIdentitiesDelta_EnrichmentRaceConvertsToTombstone(t *testing.T) {
	router := &bambooDeltaTestRouter{
		t: t,
		changed: map[string]bambooChangedTestEmployee{
			"12345": {Action: "Inserted", LastChanged: "2025-05-10T12:00:00Z"},
		},
		// No entry in enrichment for 12345 -> server replies 404
		// (employee deleted between change-feed emit and lookup).
	}
	_, c := newBambooHRTestServer(t, router.handler())

	var (
		ids     []*access.Identity
		removed []string
	)
	if _, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(batch []*access.Identity, r []string, _ string) error {
			ids = append(ids, batch...)
			removed = append(removed, r...)
			return nil
		}); err != nil {
		t.Fatalf("SyncIdentitiesDelta: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("inserts after enrichment race = %d; want 0", len(ids))
	}
	if len(removed) != 1 || removed[0] != "12345" {
		t.Errorf("removed = %v; want [12345] (race must convert to tombstone)", removed)
	}
}

func TestBambooHR_SyncIdentitiesDelta_EnrichmentNon404FailsSync(t *testing.T) {
	router := &bambooDeltaTestRouter{
		t: t,
		changed: map[string]bambooChangedTestEmployee{
			"12345": {Action: "Inserted", LastChanged: "2025-05-10T12:00:00Z"},
		},
		enrichmentFail: map[string]int{
			"12345": http.StatusInternalServerError,
		},
	}
	_, c := newBambooHRTestServer(t, router.handler())

	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil {
		t.Fatalf("expected enrichment failure to fail the sync; got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("err = %v; want status 500", err)
	}
}

func TestBambooHR_SyncIdentitiesDelta_MalformedCursorExpires(t *testing.T) {
	c := New()
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "garbage", nil)
	if !isDeltaExpired(err) {
		t.Errorf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestBambooHR_SyncIdentitiesDelta_400FromMalformedSinceExpires(t *testing.T) {
	_, c := newBambooHRTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`Invalid since timestamp`))
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !isDeltaExpired(err) {
		t.Errorf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestBambooHR_SyncIdentitiesDelta_401SurfacesAuthError(t *testing.T) {
	_, c := newBambooHRTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`unauthorized`))
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil {
		t.Fatalf("expected auth error; got nil")
	}
	if isDeltaExpired(err) {
		t.Errorf("err = %v; 401 must NOT map to ErrDeltaTokenExpired (would mask credential rot)", err)
	}
	if !strings.Contains(err.Error(), "auth failure") {
		t.Errorf("err = %v; want 'auth failure' wording so operators recognise credential rot", err)
	}
}

func TestBambooHR_SyncIdentitiesDelta_403TriggersTokenExpired(t *testing.T) {
	_, c := newBambooHRTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !isDeltaExpired(err) {
		t.Errorf("err = %v; want ErrDeltaTokenExpired (403 = plan-tier gating, full sync uses a different endpoint)", err)
	}
}

func TestBambooHR_SyncIdentitiesDelta_500PropagatesAsError(t *testing.T) {
	_, c := newBambooHRTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`boom`))
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil || isDeltaExpired(err) {
		t.Errorf("err = %v; want non-sentinel server error", err)
	}
}

func TestBambooHR_SyncIdentitiesDelta_EmptyEmployeesEmitsNothing(t *testing.T) {
	_, c := newBambooHRTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"employees": map[string]interface{}{}})
	})
	calls := 0
	cursor, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(b []*access.Identity, r []string, _ string) error {
		calls++
		if len(b) != 0 || len(r) != 0 {
			t.Errorf("non-empty batch/removed = %d / %d", len(b), len(r))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if calls != 1 {
		t.Errorf("handler calls = %d; want 1 (always invoked, even when empty)", calls)
	}
	if cursor == "" {
		t.Errorf("cursor = %q; want non-empty (must advance even on empty page so we don't replay)", cursor)
	}
	// Empty page falls back to wall-clock now() so cursor is
	// recent (within a couple of seconds).
	got, perr := time.Parse(time.RFC3339Nano, cursor)
	if perr != nil {
		// Fall back to RFC3339 in case the cursor lacks nanos.
		got, perr = time.Parse(time.RFC3339, cursor)
	}
	if perr != nil {
		t.Fatalf("cursor not RFC3339[Nano]: %q (%v)", cursor, perr)
	}
	if dt := time.Since(got); dt < 0 || dt > 5*time.Second {
		t.Errorf("cursor too far from now: %v", dt)
	}
}

func TestBambooHR_SyncIdentitiesDelta_DefaultsToOneHourLookback(t *testing.T) {
	captured := ""
	_, c := newBambooHRTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.Query().Get("since")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"employees": map[string]interface{}{}})
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// Server-side `since` is sent as RFC3339Nano so a cursor with
	// nanosecond precision actually round-trips end-to-end; RFC3339
	// is structurally a subset of RFC3339Nano so a tenant whose
	// timestamps have zero sub-second component still parses
	// cleanly here.
	ts, parseErr := time.Parse(time.RFC3339Nano, captured)
	if parseErr != nil {
		t.Fatalf("captured 'since' not RFC3339Nano: %q", captured)
	}
	if dt := time.Since(ts); dt < 30*time.Minute || dt > 2*time.Hour {
		t.Errorf("since = %v; want ~1 hour ago", ts)
	}
}

func TestBambooHR_SyncIdentitiesDelta_SinceQueryParamUsesNanoPrecision(t *testing.T) {
	// Lock in that the `since` query parameter is RFC3339Nano on
	// the wire so the +1ns cursor advancement is not silently
	// truncated by formatting. Without this round-trip, every
	// invocation re-fetches and re-processes the boundary event.
	captured := ""
	_, c := newBambooHRTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.Query().Get("since")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"employees": map[string]interface{}{}})
	})
	// Feed a cursor with explicit nanos.
	inputCursor := "2025-05-10T12:00:00.000000001Z"
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), inputCursor,
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	gotTS, perr := time.Parse(time.RFC3339Nano, captured)
	if perr != nil {
		t.Fatalf("captured 'since' not RFC3339Nano: %q (%v)", captured, perr)
	}
	if gotTS.Nanosecond() != 1 {
		t.Errorf("nanos = %d; want 1 (cursor advancement defeated by RFC3339 truncation)", gotTS.Nanosecond())
	}
}

func TestBambooHR_SyncIdentitiesDelta_CursorBasedOnMaxLastChanged(t *testing.T) {
	router := &bambooDeltaTestRouter{
		t: t,
		changed: map[string]bambooChangedTestEmployee{
			// Only deletes — should still set the cursor based
			// on max(lastChanged), regardless of action.
			"a": {Action: "Deleted", LastChanged: "2025-05-10T09:00:00Z"},
			"b": {Action: "Deleted", LastChanged: "2025-05-10T15:30:00Z"},
		},
	}
	_, c := newBambooHRTestServer(t, router.handler())
	cursor, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T08:00:00Z",
		func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	got, perr := time.Parse(time.RFC3339Nano, cursor)
	if perr != nil {
		t.Fatalf("cursor not RFC3339Nano: %q (%v)", cursor, perr)
	}
	want := time.Date(2025, 5, 10, 15, 30, 0, 1, time.UTC)
	if !got.Equal(want) {
		t.Errorf("cursor = %s; want %s (max(lastChanged)+1ns derived from page, not wall clock)", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

func TestBambooHR_SatisfiesIdentityDeltaSyncerInterface(t *testing.T) {
	var _ access.IdentityDeltaSyncer = New()
}

func TestBambooHR_InitialDeltaCursor_RoundTripsThroughParseBambooTime(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	parsed := parseBambooTime(cursor)
	if parsed.IsZero() {
		t.Fatalf("seeded cursor %q rejected by parseBambooTime", cursor)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded cursor %q is more than 5s in the past", cursor)
	}
}

// isDeltaExpired returns true when err is ErrDeltaTokenExpired (or
// wraps it). Hoisted to deflake test-file imports.
func isDeltaExpired(err error) bool {
	if err == nil {
		return false
	}
	type unwrapper interface{ Unwrap() error }
	for {
		if err == access.ErrDeltaTokenExpired {
			return true
		}
		uw, ok := err.(unwrapper)
		if !ok {
			return false
		}
		next := uw.Unwrap()
		if next == nil {
			return false
		}
		err = next
	}
}
