package jotform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func jotformValidConfig() map[string]interface{} { return map[string]interface{}{} }
func jotformValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "jotform_demo"}
}

func TestJotformConnectorFlow_FullLifecycle(t *testing.T) {
	const subID = "sub_alice"
	const email = "alice@example.com"
	const perm = "viewer"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") == "" && r.Header.Get("Authorization") == "" {
			t.Errorf("apikey/authorization header missing")
		}
		subUsersPath := "/user/sub-users"
		subUserPath := "/user/sub-users/" + subID
		emailPath := "/user/sub-users/" + email
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == subUsersPath:
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"already_exists"}`))
				return
			}
			state = perm
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"content":{"id":"` + subID + `","email":"` + email + `","permission":"` + perm + `"}}`))
		case r.Method == http.MethodDelete && (r.URL.Path == subUserPath || r.URL.Path == emailPath):
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && (r.URL.Path == subUserPath || r.URL.Path == emailPath):
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"content":{"id":"` + subID + `","email":"` + email + `","permission":"` + state + `"}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := jotformValidConfig()
	secrets := jotformValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: perm}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, subID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != perm || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with role=%s source=direct", ents, perm)
	}
	revokeGrant := access.AccessGrant{UserExternalID: subID, ResourceExternalID: perm}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, revokeGrant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, subID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestJotformConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		jotformValidConfig(), jotformValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "viewer"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
