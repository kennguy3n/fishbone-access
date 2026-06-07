package tailscale

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

func tailscaleValidConfig() map[string]interface{} {
	return map[string]interface{}{"tailnet": "example.com"}
}
func tailscaleValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "tskey-AAAA-12345"}
}

func TestTailscaleConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "user-42@example.com"
	const deviceID = "dev-9"
	authorized := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, _, ok := r.BasicAuth(); !ok || u == "" {
			t.Errorf("basic auth missing: %q", u)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/device/"+deviceID+"/authorized":
			b, _ := io.ReadAll(r.Body)
			body := string(b)
			switch {
			case strings.Contains(body, `"authorized":true`):
				if authorized {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"message":"device already authorized"}`))
					return
				}
				authorized = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			case strings.Contains(body, `"authorized":false`):
				if !authorized {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"device not found"}`))
					return
				}
				authorized = false
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/example.com/devices":
			devices := []map[string]interface{}{}
			if authorized {
				devices = append(devices, map[string]interface{}{
					"id":         deviceID,
					"name":       "node1",
					"user":       userID,
					"authorized": true,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"devices": devices})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := tailscaleValidConfig()
	secrets := tailscaleValidSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: deviceID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != deviceID {
		t.Fatalf("ents = %#v, want 1 with deviceID=%s", ents, deviceID)
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

func TestTailscaleConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		tailscaleValidConfig(),
		tailscaleValidSecrets(),
		access.AccessGrant{UserExternalID: "user-42", ResourceExternalID: "dev-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
