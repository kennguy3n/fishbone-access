package stripe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func stripeValidConfig() map[string]interface{} { return map[string]interface{}{} }
func stripeValidSecrets() map[string]interface{} {
	return map[string]interface{}{"secret_key": "sk_test_AAAA"}
}

func TestStripeConnectorFlow_FullLifecycle(t *testing.T) {
	const account = "acct_1A"
	const capability = "card_payments"
	requested := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer auth")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/accounts/"+account+"/capabilities/"+capability:
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			switch r.Form.Get("requested") {
			case "true":
				requested = true
			case "false":
				requested = false
			default:
				t.Errorf("unexpected requested value %q", r.Form.Get("requested"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": capability, "status": "active", "requested": requested})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/accounts/"+account+"/capabilities":
			data := []map[string]interface{}{}
			if requested {
				data = append(data, map[string]interface{}{"id": capability, "status": "active"})
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
	cfg := stripeValidConfig()
	secrets := stripeValidSecrets()
	grant := access.AccessGrant{UserExternalID: account, ResourceExternalID: capability}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, account)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != capability {
		t.Fatalf("ents = %#v, want 1 with capability=%s", ents, capability)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, account)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestStripeConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		stripeValidConfig(), stripeValidSecrets(),
		access.AccessGrant{UserExternalID: "acct_1A", ResourceExternalID: "card_payments"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
