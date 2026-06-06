package zendesk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises Zendesk's
// /api/v2/group_memberships endpoints. The grant.ResourceExternalID
// double-serves as both the group_id (for provision) and the
// group_membership id (for revoke) — the connector contract treats
// them as one external id.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var member atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/group_memberships.json"):
			member.Store(true)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"group_membership":{"id":42}}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/group_memberships/123.json"):
			member.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/users/u-1/group_memberships.json"):
			if member.Load() {
				_, _ = w.Write([]byte(`{"group_memberships":[{"group_id":123}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"group_memberships":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "123"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("ListEntitlements after provision: got 0, want >=1")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

// TestListEntitlements_UnparseableBodyErrors is a regression test: a 2xx
// response whose body does not parse as JSON (e.g. an HTML error page from a
// misconfigured proxy) must surface as an error, not be swallowed into
// (nil, nil) — which the caller would read as "user has no entitlements" and
// could turn into an incorrect access decision.
func TestListEntitlements_UnparseableBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>proxy error</body></html>"))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil {
		t.Fatalf("expected decode error, got nil (ents=%v)", ents)
	}
	if ents != nil {
		t.Fatalf("expected nil entitlements on decode error, got %v", ents)
	}
}

// TestGetSSOMetadata_NoSecretsRequired is a regression test: SSO metadata is
// derived purely from the subdomain config, so it must succeed even when no
// secrets are supplied (metadata may be queried before credentials are
// provisioned). Previously decodeBoth required api_token + email.
func TestGetSSOMetadata_NoSecretsRequired(t *testing.T) {
	md, err := New().GetSSOMetadata(context.Background(), validConfig(), map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetSSOMetadata without secrets: %v", err)
	}
	if md == nil || md.MetadataURL != "https://acme.zendesk.com/access/saml/metadata" {
		t.Fatalf("unexpected metadata: %+v", md)
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "123",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ProvisionAccess: want 403, got %v", err)
	}
}
