package ga4

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func ga4ValidConfig() map[string]interface{} {
	return map[string]interface{}{"account": "1234567"}
}
func ga4ValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "ga4_demo_token"}
}

// TestGA4ConnectorFlow_FullLifecycle locks in the contract: the
// caller addresses a GA4 admin entirely by the user's email address (the
// same value that ProvisionAccess sends as `emailAddress` and that
// SyncIdentities surfaces as Identity.ExternalID). RevokeAccess and
// ListEntitlements resolve email → resource name client-side via
// /v1beta/accounts/{account}/userLinks pagination before issuing the
// per-resource DELETE / GET. The mock fakes that flow exactly.
func TestGA4ConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const userLinkID = "u_alice"
	const role = "predefinedRoles/admin"
	const resourceName = "accounts/1234567/userLinks/" + userLinkID

	var mu sync.Mutex
	state := "" // "" = absent, role = present
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("authorization header missing")
		}
		listPath := "/v1beta/accounts/1234567/userLinks"
		resourcePath := "/v1beta/" + resourceName
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == listPath:
			body, _ := io.ReadAll(r.Body)
			var payload map[string]interface{}
			_ = json.Unmarshal(body, &payload)
			if got, _ := payload["emailAddress"].(string); got != email {
				t.Errorf("emailAddress = %q, want %q", got, email)
			}
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":409,"status":"ALREADY_EXISTS"}}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"` + resourceName + `","emailAddress":"` + email + `","directRoles":["` + role + `"]}`))
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			if state == "" {
				_, _ = w.Write([]byte(`{"userLinks":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"userLinks":[{"name":"` + resourceName + `","emailAddress":"` + email + `","directRoles":["` + state + `"]}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == resourcePath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := ga4ValidConfig()
	secrets := ga4ValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with role=%s source=direct", ents, role)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, email)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

// TestGA4ConnectorFlow_RevokeAcceptsResourceName confirms the resource-name
// fast path: when grant.UserExternalID is already a full GA4 userLink
// resource name (`accounts/{account}/userLinks/{id}` — the shape exposed by
// SyncIdentities via Identity.RawData["name"]) the connector issues a
// single GET /v1beta/{name} instead of paginating /userLinks, and never
// touches the list endpoint at all.
func TestGA4ConnectorFlow_RevokeAcceptsResourceName(t *testing.T) {
	const email = "bob@example.com"
	const userLinkID = "u_bob"
	const role = "predefinedRoles/viewer"
	const resourceName = "accounts/1234567/userLinks/" + userLinkID

	var mu sync.Mutex
	present := true
	var listCalls, getCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1beta/accounts/1234567/userLinks":
			listCalls++
			t.Errorf("fast path should not hit list endpoint: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		case r.Method == http.MethodGet && r.URL.Path == "/v1beta/"+resourceName:
			getCalls++
			if !present {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"name":"` + resourceName + `","emailAddress":"` + email + `","directRoles":["` + role + `"]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1beta/"+resourceName:
			present = false
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: resourceName, ResourceExternalID: role}
	if err := c.RevokeAccess(context.Background(), ga4ValidConfig(), ga4ValidSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess by resource name: %v", err)
	}
	if present {
		t.Fatalf("expected DELETE to clear state")
	}
	mu.Lock()
	defer mu.Unlock()
	if listCalls != 0 {
		t.Fatalf("listCalls = %d, want 0 (fast path)", listCalls)
	}
	if getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1", getCalls)
	}
}

// TestGA4ConnectorFlow_RevokeRolePresenceGuard locks in the
// `grant.ResourceExternalID` presence guard: when the userLink exists
// but its directRoles do NOT include the requested role, RevokeAccess
// must return nil without issuing a DELETE
// (otherwise GA4's per-userLink DELETE would silently wipe unrelated
// directRoles attached to the same admin).
func TestGA4ConnectorFlow_RevokeRolePresenceGuard(t *testing.T) {
	const email = "carol@example.com"
	const resourceName = "accounts/1234567/userLinks/u_carol"

	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1beta/accounts/1234567/userLinks":
			_, _ = w.Write([]byte(`{"userLinks":[{"name":"` + resourceName + `","emailAddress":"` + email + `","directRoles":["predefinedRoles/admin","predefinedRoles/editor"]}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1beta/"+resourceName:
			deleteCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	// User has [admin, editor]; revoke "viewer" — not present, so DELETE
	// must be skipped to preserve admin + editor.
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: "predefinedRoles/viewer"}
	if err := c.RevokeAccess(context.Background(), ga4ValidConfig(), ga4ValidSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if deleteCalls != 0 {
		t.Fatalf("deleteCalls = %d, want 0 (role absent → idempotent)", deleteCalls)
	}
}

// TestGA4ConnectorFlow_RevokeNotFoundIdempotent verifies that the
// errGA4UserLinkNotFound sentinel from findUserLinkByExternalID is
// translated by RevokeAccess into a nil return (idempotent) rather than
// propagated as an error.
func TestGA4ConnectorFlow_RevokeNotFoundIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1beta/accounts/1234567/userLinks":
			_, _ = w.Write([]byte(`{"userLinks":[]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "ghost@example.com", ResourceExternalID: "predefinedRoles/admin"}
	if err := c.RevokeAccess(context.Background(), ga4ValidConfig(), ga4ValidSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

func TestGA4ConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		ga4ValidConfig(), ga4ValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "predefinedRoles/admin"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
