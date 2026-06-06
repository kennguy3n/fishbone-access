package checkpoint

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func checkpointValidConfig() map[string]interface{} { return map[string]interface{}{} }
func checkpointValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "chkp_demo"}
}

func TestCheckPointConnectorFlow_FullLifecycle(t *testing.T) {
	const userName = "admin_alice"
	const profile = "Read Only All"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-chkp-sid") == "" {
			t.Errorf("X-chkp-sid header missing")
		}
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(body, &payload)
		name, _ := payload["name"].(string)
		switch r.URL.Path {
		case "/web_api/add-administrator":
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"code":"already_exists"}`))
				return
			}
			state = profile
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"` + name + `","permissions-profile":"` + profile + `"}`))
		case "/web_api/delete-administrator":
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusOK)
		case "/web_api/show-administrator":
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"name":"` + name + `","permissions-profile":"` + state + `"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := checkpointValidConfig()
	secrets := checkpointValidSecrets()
	grant := access.AccessGrant{UserExternalID: userName, ResourceExternalID: profile}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userName)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != profile || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with profile=%s source=direct", ents, profile)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userName)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestCheckPointConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		checkpointValidConfig(), checkpointValidSecrets(),
		access.AccessGrant{UserExternalID: "admin_alice", ResourceExternalID: "Read Only All"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
