package paypal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func paypalValidConfig() map[string]interface{} {
	return map[string]interface{}{"partner_id": "PARTNER-1", "sandbox": true}
}

func paypalValidSecrets() map[string]interface{} {
	return map[string]interface{}{"client_id": "id-AAAA", "client_secret": "sec-BBBB"}
}

func TestPayPalConnectorFlow_FullLifecycle(t *testing.T) {
	const tracking = "merchant-1"
	const feature = "PAYMENT"
	active := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"tok-123"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/customer/partner-referrals":
			if r.Header.Get("Authorization") != "Bearer tok-123" {
				t.Errorf("missing bearer")
			}
			if active {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"name":"DUPLICATE_TRACKING_ID"}`))
				return
			}
			active = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/customer/partners/PARTNER-1/merchant-integrations/"+tracking:
			if !active {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			active = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/customer/partners/PARTNER-1/merchant-integrations":
			mis := []map[string]interface{}{}
			if active {
				mis = append(mis, map[string]interface{}{
					"merchant_id":         "MID-1",
					"tracking_id":         tracking,
					"payments_receivable": true,
					"granted_permissions": []map[string]string{{"name": feature}},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"merchant_integrations": mis})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := paypalValidConfig()
	secrets := paypalValidSecrets()
	grant := access.AccessGrant{UserExternalID: tracking, ResourceExternalID: feature}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, tracking)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != feature {
		t.Fatalf("ents = %#v, want 1 with feature=%s", ents, feature)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, tracking)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestPayPalConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/oauth2/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok-x"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		paypalValidConfig(), paypalValidSecrets(),
		access.AccessGrant{UserExternalID: "merchant-1", ResourceExternalID: "PAYMENT"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
