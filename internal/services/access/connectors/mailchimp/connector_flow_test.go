package mailchimp

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func mailchimpValidConfig() map[string]interface{} {
	return map[string]interface{}{"list_id": "list1abc"}
}
func mailchimpValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "key-AAAA-us12"}
}

func mcHash(email string) string {
	sum := md5.Sum([]byte(strings.ToLower(email)))
	return hex.EncodeToString(sum[:])
}

func TestMailchimpConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const listID = "list1abc"
	hash := mcHash(email)
	memberPath := "/3.0/lists/" + listID + "/members/" + hash
	subscribed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("missing basic auth")
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == memberPath:
			subscribed = true
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"email_address": email, "status": "subscribed",
			})
		case r.Method == http.MethodDelete && r.URL.Path == memberPath:
			if !subscribed {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			subscribed = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == memberPath:
			if !subscribed {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"email_address": email, "status": "subscribed",
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
	cfg := mailchimpValidConfig()
	secrets := mailchimpValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: listID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != listID {
		t.Fatalf("ents = %#v, want 1 with listID=%s", ents, listID)
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
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestMailchimpConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		mailchimpValidConfig(), mailchimpValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "list1abc"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
