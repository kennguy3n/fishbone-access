package virustotal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func vtValidConfig() map[string]interface{} { return map[string]interface{}{} }
func vtValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "vt-api-key-AAAA"}
}

func TestVirusTotalConnectorFlow_FullLifecycle(t *testing.T) {
	const user = "alice"
	const group = "premium-group"

	var mu sync.Mutex
	state := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") == "" {
			t.Errorf("api key missing")
		}
		members := "/api/v3/groups/" + group + "/relationships/users"
		member := members + "/" + user
		userGroups := "/api/v3/users/" + user + "/groups"
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == members:
			if state {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"exists"}`))
				return
			}
			state = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == member:
			if !state {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == userGroups:
			if !state {
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"type":"group","id":"` + group + `"}]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := vtValidConfig()
	secrets := vtValidSecrets()
	grant := access.AccessGrant{UserExternalID: user, ResourceExternalID: group}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != group || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with id=%s source=direct", ents, group)
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

func TestVirusTotalConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		vtValidConfig(), vtValidSecrets(),
		access.AccessGrant{UserExternalID: "alice", ResourceExternalID: "premium-group"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
