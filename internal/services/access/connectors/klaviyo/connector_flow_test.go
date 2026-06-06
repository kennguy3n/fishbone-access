package klaviyo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func klaviyoValidConfig() map[string]interface{} { return map[string]interface{}{} }
func klaviyoValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "key-AAAA"}
}

func TestKlaviyoConnectorFlow_FullLifecycle(t *testing.T) {
	const profileID = "01HXP"
	const listID = "Lxyz"
	subscribed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Klaviyo-API-Key ") {
			t.Errorf("missing klaviyo auth")
		}
		if r.Header.Get("revision") == "" {
			t.Errorf("missing revision header")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/lists/"+listID+"/relationships/profiles":
			if subscribed {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"code":"duplicate"}]}`))
				return
			}
			subscribed = true
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/lists/"+listID+"/relationships/profiles":
			if !subscribed {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			subscribed = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/profiles/"+profileID+"/relationships/lists":
			data := []map[string]string{}
			if subscribed {
				data = append(data, map[string]string{"type": "list", "id": listID})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := klaviyoValidConfig()
	secrets := klaviyoValidSecrets()
	grant := access.AccessGrant{UserExternalID: profileID, ResourceExternalID: listID}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, profileID)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != listID {
		t.Fatalf("ents = %#v, want 1 with listID=%s", ents, listID)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, profileID)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestKlaviyoConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		klaviyoValidConfig(), klaviyoValidSecrets(),
		access.AccessGrant{UserExternalID: "01HXP", ResourceExternalID: "Lxyz"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
