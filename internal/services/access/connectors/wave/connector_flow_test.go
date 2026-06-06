package wave

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
	const userID = "usr-7"
	const resID = "role-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/graphql/public" {
			t.Errorf("path = %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		switch {
		case strings.Contains(s, "userRoleAssign"):
			resp := map[string]interface{}{"data": map[string]interface{}{"userRoleAssign": map[string]interface{}{"didSucceed": true}}}
			if isMember {
				resp = map[string]interface{}{"data": map[string]interface{}{"userRoleAssign": map[string]interface{}{"didSucceed": false, "errors": []map[string]interface{}{{"code": "ALREADY_ASSIGNED", "message": "already assigned"}}}}}
			}
			isMember = true
			_ = json.NewEncoder(w).Encode(resp)
		case strings.Contains(s, "userRoleRemove"):
			resp := map[string]interface{}{"data": map[string]interface{}{"userRoleRemove": map[string]interface{}{"didSucceed": true}}}
			if !isMember {
				resp = map[string]interface{}{"data": map[string]interface{}{"userRoleRemove": map[string]interface{}{"didSucceed": false, "errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "not assigned"}}}}}
			}
			isMember = false
			_ = json.NewEncoder(w).Encode(resp)
		case strings.Contains(s, "userRoles"):
			roles := []map[string]interface{}{}
			if isMember {
				roles = append(roles, map[string]interface{}{"id": resID, "name": "Admin"})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"userRoles": roles}})
		default:
			t.Errorf("unexpected body: %s", s)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := validConfig()
	secrets := validSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: resID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != resID {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
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
	err := c.ProvisionAccess(context.Background(),
		validConfig(),
		validSecrets(),
		access.AccessGrant{UserExternalID: "usr-7", ResourceExternalID: "role-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
