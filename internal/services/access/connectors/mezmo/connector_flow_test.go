package mezmo

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
	const email = "user@example.com"
	const role = "admin"
	added := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "servicekey ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/config/members":
			body, _ := io.ReadAll(r.Body)
			var got map[string]string
			_ = json.Unmarshal(body, &got)
			if got["email"] != email || got["role"] != role {
				t.Errorf("body = %s", string(body))
			}
			if added {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"member already exists"}`))
				return
			}
			added = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"_id":"m-1"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/config/members/"+email:
			if !added {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			added = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/config/members":
			if added {
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{"_id": "m-1", "email": email, "role": role},
				})
			} else {
				_ = json.NewEncoder(w).Encode([]interface{}{})
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	secrets := map[string]interface{}{"service_key": "sk-test"}
	cfg := map[string]interface{}{}
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
	if len(ents) != 1 || ents[0].Role != role {
		t.Fatalf("ents = %#v", ents)
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
		map[string]interface{}{"service_key": "sk-test"},
		access.AccessGrant{UserExternalID: "u@example.com", ResourceExternalID: "admin"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
