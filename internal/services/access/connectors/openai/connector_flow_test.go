package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func openaiValidConfig() map[string]interface{} { return map[string]interface{}{} }
func openaiValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "sk-admin-AAAA"}
}

func TestOpenAIConnectorFlow_FullLifecycle(t *testing.T) {
	const user = "alice@example.com"
	const role = "reader"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		users := "/v1/organization/users"
		userPath := users + "/" + user
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == users:
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"message":"user already exists"}}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"` + user + `","email":"` + user + `","role":"` + role + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id": user, "email": user, "role": state,
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
	cfg := openaiValidConfig()
	secrets := openaiValidSecrets()
	grant := access.AccessGrant{UserExternalID: user, ResourceExternalID: role}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, user)
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
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, user)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestOpenAIConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		openaiValidConfig(), openaiValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "reader"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
