package cloudsigma

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func csValidConfig() map[string]interface{} {
	return map[string]interface{}{"region": "zrh"}
}
func csValidSecrets() map[string]interface{} {
	return map[string]interface{}{"email": "alice@example.com", "password": "pw-AAAA"}
}

func TestCloudSigmaConnectorFlow_FullLifecycle(t *testing.T) {
	const ownerUUID = "owner-1"
	const aclUUID = "acl-9"
	exists := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("missing Basic auth: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/2.0/acl/":
			if exists {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"detail":"already exists"}`))
				return
			}
			exists = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/2.0/acl/"+aclUUID+"/":
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			exists = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/2.0/acl/" && r.URL.Query().Get("owner") == ownerUUID:
			objects := []map[string]interface{}{}
			if exists {
				objects = append(objects, map[string]interface{}{
					"uuid":  aclUUID,
					"name":  "default",
					"owner": map[string]string{"uuid": ownerUUID},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"objects": objects})
		default:
			t.Errorf("unexpected %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := csValidConfig()
	secrets := csValidSecrets()
	grant := access.AccessGrant{UserExternalID: ownerUUID, ResourceExternalID: aclUUID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, ownerUUID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != aclUUID {
		t.Fatalf("ents = %#v, want 1 with aclUUID=%s", ents, aclUUID)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, ownerUUID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestCloudSigmaConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		csValidConfig(), csValidSecrets(),
		access.AccessGrant{UserExternalID: "owner-1", ResourceExternalID: "acl-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
