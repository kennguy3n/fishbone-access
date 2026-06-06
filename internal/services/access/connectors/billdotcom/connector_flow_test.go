package billdotcom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func billValidConfig() map[string]interface{} {
	return map[string]interface{}{"org_id": "00ABC123"}
}

func billValidSecrets() map[string]interface{} {
	return map[string]interface{}{"dev_key": "devkey-AAAA", "session_token": "sess-BBBB"}
}

func TestBillDotComConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const role = "ADMIN"
	hasUser := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("devKey")) == "" {
			t.Errorf("missing devKey header")
		}
		if strings.TrimSpace(r.Header.Get("sessionId")) == "" {
			t.Errorf("missing sessionId header")
		}
		listPath := "/v3/orgs/00ABC123/users"
		delPath := listPath + "/" + email
		switch {
		case r.Method == http.MethodPost && r.URL.Path == listPath:
			if hasUser {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"user already exists"}`))
				return
			}
			hasUser = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"u-1","email":"` + email + `","role":"` + role + `","active":true}`))
		case r.Method == http.MethodDelete && r.URL.Path == delPath:
			if !hasUser {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hasUser = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			users := []map[string]interface{}{}
			if hasUser && r.URL.Query().Get("email") == email {
				users = append(users, map[string]interface{}{
					"id":     "u-1",
					"email":  email,
					"role":   role,
					"active": true,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := billValidConfig()
	secrets := billValidSecrets()
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
	if len(ents) != 1 || ents[0].ResourceExternalID != role {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, role)
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

func TestBillDotComConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		billValidConfig(), billValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "ADMIN"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
