package notion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "secret_1234567890abcdef"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingToken(t *testing.T) {
	if err := New().Validate(context.Background(), nil, map[string]interface{}{}); err == nil {
		t.Error("missing api_token: want error")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_Paginates(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Notion-Version") == "" {
			t.Errorf("missing Notion-Version header")
		}
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{
				"results":[{"object":"user","id":"u1","type":"person","name":"Alice","person":{"email":"alice@uney.com"}}],
				"has_more":true,
				"next_cursor":"cur2"
			}`))
			return
		}
		if r.URL.Query().Get("start_cursor") != "cur2" {
			t.Errorf("start_cursor = %q", r.URL.Query().Get("start_cursor"))
		}
		_, _ = w.Write([]byte(`{
			"results":[{"object":"user","id":"u2","type":"bot","name":"Bot","bot":{"owner":{"type":"workspace"}}}],
			"has_more":false,
			"next_cursor":null
		}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), nil, validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2", len(got))
	}
	if got[1].Type != access.IdentityTypeServiceAccount {
		t.Errorf("bot type = %q", got[1].Type)
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), nil, validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestGetCredentialsMetadata(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md["api_version"] != notionAPIVersion {
		t.Errorf("api_version = %v", md["api_version"])
	}
}

// ---------- advanced capability tests ----------

func TestProvisionAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
}

func TestProvisionAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"already"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
		t.Fatalf("ProvisionAccess idempotent: %v", err)
	}
}

// TestProvisionAccess_IdempotentConflictAndCase verifies the
// docs/architecture.md §2 idempotency contract: a 409 Conflict MUST be treated
// as success, and a capitalized "Already shared" body (returned with a 400)
// MUST also be treated as success. The pre-fix code only accepted HTTP 200 and
// did a case-sensitive substring match on lowercase "already", so both of
// these provider responses were wrongly surfaced as errors.
func TestProvisionAccess_IdempotentConflictAndCase(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"conflict_409", http.StatusConflict, `{"message":"Conflict"}`},
		{"capitalized_already_400", http.StatusBadRequest, `{"message":"Already shared with this user"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.httpClient = func() httpDoer { return srv.Client() }
			if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
				t.Fatalf("ProvisionAccess(%s): expected idempotent success, got %v", tc.name, err)
			}
		})
	}
}

func TestProvisionAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

func TestRevokeAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
		t.Fatalf("RevokeAccess idempotent: %v", err)
	}
}

func TestRevokeAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"person","name":"Alice"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
}

func TestListEntitlements_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d, want 0", len(got))
	}
}

func TestListEntitlements_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"object":"error","status":500}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "u-1")
	if err == nil {
		t.Fatal("expected HTTP error to propagate, got nil")
	}
	if got != nil {
		t.Fatalf("expected nil entitlements on error, got %+v", got)
	}
}

func TestSyncIdentities_EncodesCursor(t *testing.T) {
	// A checkpoint cursor containing URL-special characters must be sent
	// verbatim (percent-encoded), not concatenated raw into the query string.
	const weird = "a+b/c=d&e"
	var gotCursor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCursor = r.URL.Query().Get("start_cursor")
		_, _ = w.Write([]byte(`{"results":[],"has_more":false,"next_cursor":null}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), nil, validSecrets(), weird,
		func(_ []*access.Identity, _ string) error { return nil })
	if err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if gotCursor != weird {
		t.Fatalf("start_cursor = %q; want %q", gotCursor, weird)
	}
}

// captureProvisionRole runs ProvisionAccess against a mock that records the
// "role" sent in the first permissions entry of the PATCH body.
func captureProvisionRole(t *testing.T, grant access.AccessGrant) string {
	t.Helper()
	var gotRole string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Permissions []struct {
				Role string `json:"role"`
			} `json:"permissions"`
		}
		_ = json.Unmarshal(raw, &body)
		if len(body.Permissions) > 0 {
			gotRole = body.Permissions[0].Role
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	return gotRole
}

// TestProvisionAccess_HonorsGrantRole verifies the connector forwards the
// caller's requested role instead of hardcoding "editor". Pre-fix the payload
// always carried "editor", so a read-only grant was silently escalated to
// write access.
func TestProvisionAccess_HonorsGrantRole(t *testing.T) {
	if got := captureProvisionRole(t, access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1", Role: "reader"}); got != "reader" {
		t.Errorf("role=%q; want the requested role \"reader\" (not a hardcoded editor)", got)
	}
	// An unset role falls back to the historical "editor" default.
	if got := captureProvisionRole(t, access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); got != "editor" {
		t.Errorf("role=%q; want default \"editor\" when grant.Role is empty", got)
	}
}

// TestRevokeAccess_Accepts2xx verifies RevokeAccess treats the full 2xx range
// as success. Pre-fix only 200/404 were accepted, so a 204 No Content (a
// plausible response for a permission-clearing PATCH) was wrongly surfaced as
// an error to the leaver flow.
func TestRevokeAccess_Accepts2xx(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusAccepted} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		c := New()
		c.urlOverride = srv.URL
		c.httpClient = func() httpDoer { return srv.Client() }
		if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
			t.Errorf("RevokeAccess on %d: %v; want nil (2xx is success)", status, err)
		}
		srv.Close()
	}
}

// TestProvisionRevoke_RejectWhitespaceIDs verifies grant IDs are trimmed before
// the emptiness check, matching every other connector in the batch — a
// whitespace-only ID must be a clean validation error, not sent to the API.
func TestProvisionRevoke_RejectWhitespaceIDs(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cases := []access.AccessGrant{
		{UserExternalID: "   ", ResourceExternalID: "page-1"},
		{UserExternalID: "u-1", ResourceExternalID: "  "},
	}
	for _, g := range cases {
		if err := c.ProvisionAccess(context.Background(), nil, validSecrets(), g); err == nil {
			t.Errorf("ProvisionAccess(%+v): err=nil; want validation error", g)
		}
		if err := c.RevokeAccess(context.Background(), nil, validSecrets(), g); err == nil {
			t.Errorf("RevokeAccess(%+v): err=nil; want validation error", g)
		}
	}
	// A whitespace-only ID must be rejected by local validation before any
	// API call — pre-fix the untrimmed check let it through to the server.
	if hits != 0 {
		t.Errorf("server received %d request(s); want 0 (whitespace IDs must fail validation locally)", hits)
	}
}

// TestRevokeAccess_TargetsOnlyGrantUser verifies RevokeAccess removes ONLY the
// target user's permission instead of clearing the whole page. Pre-fix the body
// was {"permissions":[]} — an empty array that semantically strips every
// collaborator (a full replace), so revoking user A would also drop B and C.
// The fix sends the single target user with role "none", scoping the revoke to
// exactly that principal.
func TestRevokeAccess_TargetsOnlyGrantUser(t *testing.T) {
	type perm struct {
		Type   string `json:"type"`
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	var got struct {
		Permissions []perm `json:"permissions"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "page-1"}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	// An empty permissions payload is over-revocation: it would clear every
	// collaborator on the page, not just the leaver.
	if len(got.Permissions) != 1 {
		t.Fatalf("permissions=%+v; want exactly 1 entry scoped to the target user (empty array over-revokes the whole page)", got.Permissions)
	}
	if got.Permissions[0].UserID != "u-1" {
		t.Errorf("user_id=%q; want the target %q so only that user is revoked", got.Permissions[0].UserID, "u-1")
	}
	if got.Permissions[0].Type != "user" {
		t.Errorf("type=%q; want \"user\"", got.Permissions[0].Type)
	}
}
