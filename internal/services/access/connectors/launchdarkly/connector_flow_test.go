package launchdarkly

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const memberID = "member-1"
	const role = "release-engineer"
	hasRole := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v2/members/"+memberID:
			b, _ := io.ReadAll(r.Body)
			var patch []map[string]interface{}
			_ = json.Unmarshal(b, &patch)
			if len(patch) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			op, _ := patch[0]["op"].(string)
			switch op {
			case "add":
				if hasRole {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"message":"custom role already exists for member"}`))
					return
				}
				hasRole = true
				w.WriteHeader(http.StatusOK)
			case "remove":
				if !hasRole {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"message":"custom role does not exist for member"}`))
					return
				}
				hasRole = false
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/members/"+memberID:
			roles := []string{}
			if hasRole {
				roles = []string{role}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"_id": memberID, "customRoles": roles,
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	secrets := map[string]interface{}{"api_key": "k"}
	cfg := map[string]interface{}{}
	grant := access.AccessGrant{UserExternalID: memberID, ResourceExternalID: role}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, memberID)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, memberID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %d", len(ents))
	}
}

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), map[string]interface{}{},
		map[string]interface{}{"api_key": "k"},
		access.AccessGrant{UserExternalID: "m", ResourceExternalID: "r"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
