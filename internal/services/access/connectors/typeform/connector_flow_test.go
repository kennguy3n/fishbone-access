package typeform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func typeformValidConfig() map[string]interface{} { return map[string]interface{}{} }
func typeformValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "tfp_demo"}
}

func TestTypeformConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const workspace = "ws-1"
	const role = "editor"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		members := "/workspaces/" + workspace + "/members"
		memberPath := members + "/" + email
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == members:
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"description":"member exists"}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == memberPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/workspaces":
			// Real Typeform shape: GET /workspaces returns workspace
			// objects whose membership lives in a nested `members` array
			// (email + role), not a top-level per-user field.
			if state == "" {
				_, _ = w.Write([]byte(`{"items":[{"id":"` + workspace + `","members":[]}],"page_count":1}`))
				return
			}
			_, _ = w.Write([]byte(`{"items":[{"id":"` + workspace + `","members":[{"email":"` + email + `","role":"` + state + `"}]}],"page_count":1}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := typeformValidConfig()
	secrets := typeformValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: workspace + ":" + role}

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
	if len(ents) != 1 || ents[0].Role != role || ents[0].Source != "direct" {
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

// TestTypeformListEntitlements_PaginatesAndMatchesNestedMembers verifies the
// corrected ListEntitlements: it walks every page of GET /workspaces and reads
// the requested user's role out of each workspace's nested `members` array.
// The target user lives only on a workspace returned on page 2. The old
// implementation hit a non-existent `/me/workspaces?email=` path and read
// top-level `items[].email`/`items[].role`, so it returned an empty (false
// "no access") result; this test serves neither of those and fails without the
// fix (page 1 never advances, page 2 never requested, members never matched).
func TestTypeformListEntitlements_PaginatesAndMatchesNestedMembers(t *testing.T) {
	const email = "carol@example.com"
	const wantWorkspace = "ws-page2"
	const wantRole = "owner"
	page2Hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/workspaces" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Query().Get("page") {
		case "1": // target absent here; a full page forces a second request
			_, _ = w.Write([]byte(`{"items":[{"id":"ws-1","members":[{"email":"someone@else.com","role":"member"}]}],"page_count":2}`))
		case "2":
			page2Hit = true
			_, _ = w.Write([]byte(`{"items":[{"id":"` + wantWorkspace + `","members":[{"email":"x@y.com","role":"member"},{"email":"` + email + `","role":"` + wantRole + `"}]}],"page_count":2}`))
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	ents, err := c.ListEntitlements(context.Background(),
		typeformValidConfig(), typeformValidSecrets(), email)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if !page2Hit {
		t.Fatalf("ListEntitlements never paginated to page 2")
	}
	if len(ents) != 1 {
		t.Fatalf("ents = %#v, want exactly 1", ents)
	}
	if ents[0].Role != wantRole || ents[0].ResourceExternalID != wantWorkspace+":"+wantRole || ents[0].Source != "direct" {
		t.Fatalf("ent = %#v, want workspace=%s role=%s source=direct", ents[0], wantWorkspace, wantRole)
	}
}

func TestTypeformConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		typeformValidConfig(), typeformValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "ws-1:editor"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
