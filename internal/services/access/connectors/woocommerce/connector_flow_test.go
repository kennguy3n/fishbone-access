package woocommerce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func woocommerceValidConfigForFlow() map[string]interface{} {
	return map[string]interface{}{"endpoint": "https://shop.example.com"}
}
func woocommerceValidSecretsForFlow() map[string]interface{} {
	return map[string]interface{}{"consumer_key": "tok_AAAA1234bbbbCCCC", "consumer_secret": "tok_AAAA1234bbbbCCCC"}
}

func TestWooCommerceConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "42"
	const userEmail = "alice@example.com"
	const role = "shop_manager"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("authorization header missing")
		}
		customers := "/wp-json/wc/v3/customers"
		userPath := customers + "/" + userID
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == customers:
			if state != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":"woocommerce_rest_user_email_exists"}`))
				return
			}
			state = role
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":` + userID + `,"email":"` + userEmail + `","role":"` + role + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"deleted":true}`))
		case r.Method == http.MethodGet && r.URL.Path == userPath:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"id":` + userID + `,"email":"` + userEmail + `","role":"` + state + `"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := woocommerceValidConfigForFlow()
	secrets := woocommerceValidSecretsForFlow()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: role}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != role || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with role=%s source=direct", ents, role)
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

func TestWooCommerceConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		woocommerceValidConfigForFlow(), woocommerceValidSecretsForFlow(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "customer"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
