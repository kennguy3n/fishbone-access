package notion

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

// TestNotionConnectorFlow_FullLifecycle exercises the advanced-cap
// contract for the Notion v1 pages/users API: PATCH /v1/pages/{page_id}
// with a `permissions` patch for both Provision and Revoke, and GET
// /v1/users/{user_id} for ListEntitlements (Notion's public API does not
// surface per-page entitlement listings, so the connector returns the
// user's account-level type as a best-effort entitlement).
func TestNotionConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "user_alice_uuid"
	const pageID = "page_beta_uuid"

	var mu sync.Mutex
	state := "" // "" = absent, "editor" = present
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("authorization header missing/invalid: %q", got)
		}
		if r.Header.Get("Notion-Version") != notionAPIVersion {
			t.Errorf("Notion-Version = %q", r.Header.Get("Notion-Version"))
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/pages/"+pageID:
			// Both Provision and Revoke hit the same PATCH endpoint with a
			// `permissions` array scoped to the target user — Provision sends
			// the granted role (e.g. "editor"), Revoke sends role "none" to
			// remove exactly that user. Decode the role to decide which
			// side-effect to apply. (A bare `"permissions":[]` would be
			// over-revocation — clearing every collaborator — which the
			// connector no longer emits.)
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			var patch struct {
				Permissions []struct {
					UserID string `json:"user_id"`
					Role   string `json:"role"`
				} `json:"permissions"`
			}
			_ = json.Unmarshal(body, &patch)
			if len(patch.Permissions) != 1 || patch.Permissions[0].UserID != userID {
				t.Errorf("PATCH permissions = %s; want a single entry scoped to %q", string(body), userID)
			}
			if len(patch.Permissions) == 1 && patch.Permissions[0].Role == "none" {
				state = ""
			} else {
				state = "editor"
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object":"page","id":"` + pageID + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/users/"+userID:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object":"user","id":"` + userID + `","type":"person","name":"Alice"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{}
	secrets := validSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: pageID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	mu.Lock()
	if state != "editor" {
		t.Fatalf("after Provision×2, mock state = %q, want %q", state, "editor")
	}
	mu.Unlock()
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with source=direct", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	mu.Lock()
	if state != "" {
		t.Fatalf("after Revoke×2, mock state = %q, want empty", state)
	}
	mu.Unlock()
}

func TestNotionConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"unauthorized"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{}, validSecrets(),
		access.AccessGrant{UserExternalID: "u_alice", ResourceExternalID: "page_beta"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want 403", err)
	}
}
