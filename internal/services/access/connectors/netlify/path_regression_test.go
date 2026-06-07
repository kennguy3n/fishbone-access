package netlify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestNetlifyMemberPathConsistency is a regression test for the bug where the
// advanced-capability operations (ProvisionAccess/RevokeAccess/ListEntitlements)
// addressed members at "/api/v1/accounts/{slug}/members" while the base
// operations used "/api/v1/{slug}/members". The official Netlify API
// (open-api.netlify.com) exposes account members at /{account_slug}/members
// with NO /accounts/ segment, so both code paths must agree on that endpoint.
//
// Unlike the per-operation tests (each with its own mock matching whatever the
// code emits), this drives base AND advanced operations against a single mock
// that serves only the spec-correct path and fails on any request carrying the
// erroneous /accounts/ segment — catching the divergence the old mocks masked.
func TestNetlifyMemberPathConsistency(t *testing.T) {
	const (
		slug  = "acme"
		email = "alice@example.com"
		role  = "Collaborator"
	)
	memberPath := "/api/v1/" + slug + "/members"
	delPath := memberPath + "/" + email

	var paths []string
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "/accounts/") {
			t.Errorf("request used erroneous /accounts/ segment (not in Netlify OpenAPI spec): %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == memberPath:
			isMember = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == delPath:
			isMember = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == memberPath:
			data := []map[string]interface{}{}
			if isMember {
				data = append(data, map[string]interface{}{"id": email, "email": email, "role": role})
			}
			_ = json.NewEncoder(w).Encode(data)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"account_slug": slug}
	secrets := map[string]interface{}{"access_token": "netlify-token-AAAA"}
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: role}
	ctx := context.Background()

	if err := c.Connect(ctx, cfg, secrets); err != nil { // base op
		t.Fatalf("Connect: %v", err)
	}
	if err := c.ProvisionAccess(ctx, cfg, secrets, grant); err != nil { // advanced
		t.Fatalf("ProvisionAccess: %v", err)
	}
	ents, err := c.ListEntitlements(ctx, cfg, secrets, email) // advanced
	if err != nil || len(ents) != 1 || ents[0].ResourceExternalID != role {
		t.Fatalf("ListEntitlements: ents=%#v err=%v", ents, err)
	}
	if err := c.RevokeAccess(ctx, cfg, secrets, grant); err != nil { // advanced
		t.Fatalf("RevokeAccess: %v", err)
	}
	if err := c.SyncIdentities(ctx, cfg, secrets, "", func(b []*access.Identity, _ string) error { return nil }); err != nil { // base op
		t.Fatalf("SyncIdentities: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, memberPath) {
			t.Errorf("request path %q does not match Netlify spec member endpoint %q", p, memberPath)
		}
	}
}

// TestNetlifyMembersURL_NoAccountsSegment pins the exact member endpoint against
// the Netlify OpenAPI spec so the /accounts/ regression cannot silently return.
func TestNetlifyMembersURL_NoAccountsSegment(t *testing.T) {
	c := New()
	got := c.membersURL("acme")
	const want = "https://api.netlify.com/api/v1/acme/members"
	if got != want {
		t.Fatalf("membersURL = %q, want %q", got, want)
	}
	if strings.Contains(got, "/accounts/") {
		t.Fatalf("membersURL must not contain /accounts/ (Netlify spec is /api/v1/{slug}/members): %q", got)
	}
}

// TestNetlifyBaseOps_EscapeAccountSlug is a regression test for the bug where
// the base operations (Connect/CountIdentities/SyncIdentities) interpolated the
// raw account_slug into the request path while the advanced operations used
// url.PathEscape. A slug containing a path-significant character ('/', '%', '?')
// would corrupt the base-op request path (e.g. "ac/me" splits into an extra
// path segment) while the advanced ops stayed correct. Routing every op through
// membersPath fixes this; the base ops must now emit the percent-escaped slug.
// Without the fix the recorded EscapedPath would be "/api/v1/ac/me/members".
func TestNetlifyBaseOps_EscapeAccountSlug(t *testing.T) {
	const slug = "ac/me"
	const wantEscaped = "/api/v1/ac%2Fme/members"

	var escaped []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped = append(escaped, r.URL.EscapedPath())
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"account_slug": slug}
	secrets := map[string]interface{}{"access_token": "netlify-token-AAAA"}
	ctx := context.Background()

	if err := c.Connect(ctx, cfg, secrets); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if _, err := c.CountIdentities(ctx, cfg, secrets); err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if err := c.SyncIdentities(ctx, cfg, secrets, "", func(b []*access.Identity, _ string) error { return nil }); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}

	if len(escaped) != 3 {
		t.Fatalf("expected 3 base-op requests, got %d: %v", len(escaped), escaped)
	}
	for _, p := range escaped {
		if p != wantEscaped {
			t.Errorf("base-op escaped path = %q, want %q (slug must be url.PathEscape'd)", p, wantEscaped)
		}
	}
}

// TestNetlifyDecodeConfig_TrimsAccountSlug pins decode-time canonicalization so
// a padded slug cannot survive into the request path or the reported metadata.
func TestNetlifyDecodeConfig_TrimsAccountSlug(t *testing.T) {
	cfg, err := DecodeConfig(map[string]interface{}{"account_slug": "  acme  "})
	if err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if cfg.AccountSlug != "acme" {
		t.Fatalf("AccountSlug = %q, want %q (decode must TrimSpace)", cfg.AccountSlug, "acme")
	}
}
