package zendesk

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

func newZendeskTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *ZendeskAccessConnector) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return srv, c
}

func TestZendesk_SyncIdentitiesDelta_HappyPath(t *testing.T) {
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v2/audit_logs.json") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"audit_logs": []map[string]interface{}{
				{
					"id":           int64(1001),
					"source_type":  "user",
					"source_id":    int64(900001),
					"source_label": "Alice",
					"action":       "create",
					"created_at":   "2025-05-10T12:00:00Z",
				},
				{
					"id":           int64(1002),
					"source_type":  "user",
					"source_id":    int64(900002),
					"source_label": "Bob",
					"action":       "update",
					"created_at":   "2025-05-10T12:05:00Z",
				},
				{
					"id":           int64(1003),
					"source_type":  "user",
					"source_id":    int64(900003),
					"source_label": "Carol",
					"action":       "destroy",
					"created_at":   "2025-05-10T12:10:00Z",
				},
				{
					"id":           int64(1004),
					"source_type":  "ticket",
					"source_id":    int64(42),
					"source_label": "TKT-42",
					"action":       "update",
					"created_at":   "2025-05-10T12:15:00Z",
				},
			},
			"next_page": "",
		})
	})
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
	if len(ids) != 2 || ids[0].ExternalID != "900001" || ids[1].ExternalID != "900002" {
		t.Errorf("identities = %+v", ids)
	}
	if ids[0].Status != "active" || ids[1].Status != "active" {
		t.Errorf("status = %q / %q", ids[0].Status, ids[1].Status)
	}
	if len(removed) != 1 || removed[0] != "900003" {
		t.Errorf("removed = %v; want [900003]", removed)
	}
	if !strings.HasPrefix(cursor, "2025-05-10T12:10:00") {
		t.Errorf("cursor = %q; want newest seen", cursor)
	}
}

func TestZendesk_SyncIdentitiesDelta_MalformedCursorExpires(t *testing.T) {
	c := New()
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "garbage", nil)
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Errorf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestZendesk_SyncIdentitiesDelta_403TriggersTokenExpired(t *testing.T) {
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"audit log not available on this plan"}`))
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if !errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Errorf("err = %v; want ErrDeltaTokenExpired", err)
	}
}

func TestZendesk_SyncIdentitiesDelta_500PropagatesAsError(t *testing.T) {
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Errorf("err = %v; want non-sentinel server error", err)
	}
}

func TestZendesk_SyncIdentitiesDelta_DefaultsToOneHourLookback(t *testing.T) {
	captured := ""
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.Query().Get("filter[created_at][]")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": []map[string]interface{}{}, "next_page": ""})
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	ts, parseErr := time.Parse(time.RFC3339, captured)
	if parseErr != nil {
		t.Fatalf("captured 'from' not RFC3339: %q", captured)
	}
	if dt := time.Since(ts); dt < 30*time.Minute || dt > 2*time.Hour {
		t.Errorf("from = %v; want ~1 hour ago", ts)
	}
}

func TestZendesk_SyncIdentitiesDelta_NoEventsKeepsCursor(t *testing.T) {
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": []map[string]interface{}{}, "next_page": ""})
	})
	cursor, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(cursor, "2025-05-10T11:00:00") {
		t.Errorf("cursor = %q; want supplied since", cursor)
	}
}

func TestZendesk_SyncIdentitiesDelta_401PropagatesAsErrorPreservingCursor(t *testing.T) {
	// 401 must NOT collapse to ErrDeltaTokenExpired — clearing the
	// cursor on auth failure would silently discard incremental
	// progress, since the follow-up full sync would also fail with
	// 401 and after credentials are fixed we'd have nothing to
	// resume from.
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil || errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Errorf("err = %v; want non-sentinel auth error", err)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v; want diagnostic to mention status 401", err)
	}
}

func TestZendesk_SyncIdentitiesDelta_500WithFalsy403InBody(t *testing.T) {
	// A 5xx whose body happens to contain the substring "status 403"
	// must NOT misclassify as ErrDeltaTokenExpired. This guards the
	// numeric-status-code refactor against regressing to the old
	// string-matching pattern.
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"upstream returned status 403; please retry"}`))
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err == nil {
		t.Fatal("want error")
	}
	if errors.Is(err, access.ErrDeltaTokenExpired) {
		t.Errorf("err = %v; 500 must not collapse to ErrDeltaTokenExpired even when body says 'status 403'", err)
	}
}

func TestZendesk_SyncIdentitiesDelta_FiltersSourceTypeServerSide(t *testing.T) {
	// Server-side filter[source_type]=user keeps payload size +
	// page count proportional to user-change volume on large
	// workspaces, instead of streaming every ticket/group/setting
	// audit row.
	captured := ""
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		captured = r.URL.Query().Get("filter[source_type]")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": []map[string]interface{}{}, "next_page": ""})
	})
	_, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if captured != "user" {
		t.Errorf("filter[source_type] = %q; want %q", captured, "user")
	}
}

func TestZendesk_SyncIdentitiesDelta_CursorIsRFC3339Nano(t *testing.T) {
	// The returned cursor must be parseable by RFC3339Nano so any
	// sub-second precision the caller fed in via deltaLink round-
	// trips symmetrically through this sync.
	_, c := newZendeskTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"audit_logs": []map[string]interface{}{}, "next_page": ""})
	})
	cursor, err := c.SyncIdentitiesDelta(context.Background(), validConfig(), validSecrets(), "2025-05-10T11:00:00.500Z", func(_ []*access.Identity, _ []string, _ string) error { return nil })
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, perr := time.Parse(time.RFC3339Nano, cursor); perr != nil {
		t.Errorf("cursor %q not parseable as RFC3339Nano: %v", cursor, perr)
	}
	// And the sub-second precision should round-trip back out.
	if !strings.HasPrefix(cursor, "2025-05-10T11:00:00.5") {
		t.Errorf("cursor %q dropped sub-second precision", cursor)
	}
}

func TestZendesk_SatisfiesIdentityDeltaSyncerInterface(t *testing.T) {
	var _ access.IdentityDeltaSyncer = New()
}

func TestZendesk_InitialDeltaCursor_RoundTripsThroughSyncIdentitiesDelta(t *testing.T) {
	c := New()
	cursor, err := c.InitialDeltaCursor(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("InitialDeltaCursor: %v", err)
	}
	// Zendesk SyncIdentitiesDelta accepts RFC3339Nano then RFC3339;
	// the seeded cursor must parse as RFC3339Nano.
	parsed, perr := time.Parse(time.RFC3339Nano, cursor)
	if perr != nil {
		t.Fatalf("seeded cursor %q failed RFC3339Nano parse: %v", cursor, perr)
	}
	if time.Since(parsed) > 5*time.Second {
		t.Errorf("seeded cursor %q is more than 5s in the past", cursor)
	}
}
