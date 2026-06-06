package onepassword

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises the full advanced-capability
// lifecycle for the 1Password SCIM bridge connector: SCIM Groups PATCH for
// provision/revoke, SCIM Users GET for list_entitlements.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/scim/v2/Groups/group-1" && r.Method == http.MethodPatch:
			body, _ := readBody(r)
			if containsOp(body, "add") {
				assigned = true
			} else if containsOp(body, "remove") {
				if !assigned {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				assigned = false
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/scim/v2/Users/user-1" && r.Method == http.MethodGet:
			detail := scimUserDetail{ID: "user-1"}
			if assigned {
				detail.Groups = []scimUserGroupRef{{Value: "group-1", Display: "Engineers"}}
			}
			_ = json.NewEncoder(w).Encode(detail)
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

	grant := access.AccessGrant{UserExternalID: "user-1", ResourceExternalID: "group-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}

	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("expected provisioned grant to appear, got 0")
	}

	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}

	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ConnectFailsWithBadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil {
		t.Fatal("Connect with 401: expected error, got nil")
	}
}

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, r.ContentLength)
	_, err := r.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return nil, err
	}
	return buf, nil
}

func containsOp(body []byte, op string) bool {
	var p scimPatchOp
	if err := json.Unmarshal(body, &p); err != nil {
		return false
	}
	for _, o := range p.Operations {
		if o.Op == op {
			return true
		}
	}
	return false
}
