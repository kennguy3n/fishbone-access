package hubspot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Regression: audit soft-skip must map 401 and 404 (not only 403) to
// access.ErrAuditNotAvailable, matching the other connectors. Before
// the fix, only "status 403" was matched via error-string, so 401/404
// surfaced as hard failures and triggered repeated worker retries.

func TestFetchAccessAuditLogs_SoftSkipStatuses(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized, // 401
		http.StatusForbidden,    // 403
		http.StatusNotFound,     // 404
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.httpClient = func() httpDoer { return srv.Client() }
			err := c.FetchAccessAuditLogs(context.Background(), validConfig(), validSecrets(),
				map[string]time.Time{access.DefaultAuditPartition: time.Now().Add(-time.Hour)},
				func(_ []*access.AuditLogEntry, _ time.Time, _ string) error { return nil })
			if err != access.ErrAuditNotAvailable {
				t.Fatalf("status %d: err = %v; want ErrAuditNotAvailable", status, err)
			}
		})
	}
}

// Regression: mapHubSpotAuditLog must normalize parsed timestamps to
// UTC like every other connector in the batch. Before the fix a
// non-UTC offset (e.g. +05:00) was carried into AuditLogEntry.Timestamp
// and the persisted nextSince cursor, producing timezone-inconsistent
// downstream data.
func TestMapHubSpotAuditLog_NormalizesToUTC(t *testing.T) {
	entry := mapHubSpotAuditLog(&hubspotAuditLog{
		ID:         "evt-1",
		OccurredAt: "2024-01-01T10:00:00+05:00",
		Action:     "update",
		ObjectType: "Contact",
	})
	if entry == nil {
		t.Fatal("entry = nil; want non-nil")
	}
	if entry.Timestamp.Location() != time.UTC {
		t.Errorf("Timestamp location = %v; want UTC", entry.Timestamp.Location())
	}
	if !entry.Timestamp.Equal(time.Date(2024, 1, 1, 5, 0, 0, 0, time.UTC)) {
		t.Errorf("Timestamp = %s; want 2024-01-01T05:00:00Z", entry.Timestamp.Format(time.RFC3339))
	}
}

// Regression: SyncIdentities cursor must be URL-encoded.  Before the
// fix, a cursor containing "&" was spliced raw, producing a malformed
// query string.

func TestSyncIdentities_CursorURLEncoded(t *testing.T) {
	const specialCursor = "a&b=c+d"
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"results":[{"id":"1","email":"a@b.com","firstName":"A"}],"paging":{"next":{"after":%q,"link":"/x"}}}`,
				specialCursor)))
			return
		}
		got := r.URL.Query().Get("after")
		if got != specialCursor {
			t.Errorf("after = %q; want %q", got, specialCursor)
		}
		_, _ = w.Write([]byte(`{"results":[{"id":"2","email":"b@b.com","firstName":"B"}],"paging":{}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2", len(got))
	}
}

// Regression: mapHubSpotAuditLog must return nil when OccurredAt is
// empty or unparseable, preventing zero-time audit entries.

func TestMapHubSpotAuditLog_ZeroTimeReturnsNil(t *testing.T) {
	for _, tc := range []struct {
		name       string
		occurredAt string
		wantNil    bool
	}{
		{"empty", "", true},
		{"garbage", "not-a-date", true},
		{"valid_rfc3339", "2024-06-01T11:00:00Z", false},
		{"valid_rfc3339nano", "2024-06-01T11:00:00.123456789Z", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := &hubspotAuditLog{ID: "evt-1", OccurredAt: tc.occurredAt, Action: "login"}
			got := mapHubSpotAuditLog(entry)
			if tc.wantNil && got != nil {
				t.Errorf("expected nil for OccurredAt=%q, got %+v", tc.occurredAt, got)
			}
			if !tc.wantNil && got == nil {
				t.Errorf("expected non-nil for OccurredAt=%q", tc.occurredAt)
			}
		})
	}
}

// Regression: ListEntitlements must surface json.Unmarshal errors
// instead of swallowing them as (nil, nil).

func TestListEntitlements_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	_, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
}

// Regression: ProvisionAccess must accept the full 2xx range, not just
// 200 and 204.  201 Created is a common HubSpot response.

func TestProvisionAccess_201Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("ProvisionAccess 201: %v", err)
	}
}

// Regression: ProvisionAccess must treat 409 Conflict (already exists)
// as idempotent success via access.IsIdempotentProvisionStatus.

func TestProvisionAccess_409Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"message":"already exists"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("ProvisionAccess 409: %v", err)
	}
}

// Regression: RevokeAccess must accept the full 2xx range.

func TestRevokeAccess_202Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("RevokeAccess 202: %v", err)
	}
}

// Regression: RevokeAccess must use IsIdempotentRevokeStatus, covering
// cases like 410 Gone with "not found" body.

func TestRevokeAccess_410Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"})
	if err != nil {
		t.Fatalf("RevokeAccess 410: %v", err)
	}
}

// Regression: ProvisionAccess must surface transient (5xx) errors
// distinctly for retry logic.

func TestProvisionAccess_TransientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "role-1"})
	if err == nil {
		t.Fatal("expected transient error")
	}
}

// Regression: ListEntitlements must treat a 404 (user not found / no
// roles) as an empty entitlement list, not a hard error, matching the
// other connectors in this batch. Before the fix c.do() turned the 404
// into an error.
func TestListEntitlements_NotFoundReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"user not found"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	out, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "missing-user")
	if err != nil {
		t.Fatalf("ListEntitlements 404: err = %v; want nil", err)
	}
	if len(out) != 0 {
		t.Fatalf("entitlements = %+v; want empty", out)
	}
}

// Regression: ProvisionAccess/RevokeAccess must reject whitespace-only
// grant fields with a local validation error (via strings.TrimSpace),
// instead of building a request path containing %20. No HTTP request
// should be made.
func TestProvisionRevoke_RejectWhitespaceGrantFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP request to %s for whitespace-only grant", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	grants := []access.AccessGrant{
		{UserExternalID: "   ", ResourceExternalID: "role-1"},
		{UserExternalID: "u-1", ResourceExternalID: "  "},
	}
	for _, g := range grants {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), g); err == nil {
			t.Errorf("ProvisionAccess(%+v): err = nil; want validation error", g)
		}
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), g); err == nil {
			t.Errorf("RevokeAccess(%+v): err = nil; want validation error", g)
		}
	}
}
