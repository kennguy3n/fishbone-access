package rapid7

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the advanced-capability
// lifecycle for the Rapid7 InsightVM connector with a single
// httptest.Server mocking /api/3/sites/{siteId}/users/{userId} (PUT,
// DELETE) and /api/3/users/{userId}/sites (GET, list).
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const siteID = "42"
	const userID = "7"
	assigned := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("expected Basic auth; got %q", got)
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == fmt.Sprintf("/api/3/sites/%s/users/%s", siteID, userID):
			if assigned {
				// Second call: provider responds with 409 to
				// confirm IsIdempotentProvisionStatus handling.
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"user already a member of site"}`))
				return
			}
			assigned = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == fmt.Sprintf("/api/3/sites/%s/users/%s", siteID, userID):
			if !assigned {
				// Second revoke: provider 404s.
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not a member"}`))
				return
			}
			assigned = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf("/api/3/users/%s/sites", userID):
			body := map[string]interface{}{
				"page": map[string]interface{}{"number": 0, "totalPages": 1},
			}
			if assigned {
				body["resources"] = []map[string]interface{}{{"id": 42, "name": "Production"}}
			} else {
				body["resources"] = []map[string]interface{}{}
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: siteID, Role: "site_user"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), userID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != siteID {
		t.Fatalf("ListEntitlements after provision: got %#v", ents)
	}

	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}

	ents, err = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), userID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: expected empty, got %d", len(ents))
	}
}

// TestConnectorFlow_ProvisionForbiddenFailure surfaces a 403 from the
// provider as a non-nil error and does not retry it (4xx is permanent).
func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"insufficient permissions"}`))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	grant := access.AccessGrant{UserExternalID: "7", ResourceExternalID: "42"}
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ProvisionAccess: expected 403 error, got %v", err)
	}
}
