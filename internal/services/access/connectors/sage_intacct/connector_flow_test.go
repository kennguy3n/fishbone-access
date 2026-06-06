package sage_intacct

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func sageValidConfig() map[string]interface{} {
	return map[string]interface{}{"company_id": "ACME"}
}
func sageValidSecrets() map[string]interface{} {
	return map[string]interface{}{
		"sender_id":       "sender-AAAA",
		"sender_password": "spw",
		"user_id":         "alice",
		"user_password":   "upw",
	}
}

func TestSageIntacctConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "bob"
	const role = "audit_user"

	var mu sync.Mutex
	state := map[string]string{} // userID -> role
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ia/xml/xmlgw.phtml" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(raw, "<create><USERINFO>"):
			if _, ok := state[userID]; ok && strings.Contains(raw, "<USERID>"+userID+"</USERID>") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><result><status>failure</status><errormessage>user already exists</errormessage></result></operation></response>`))
				return
			}
			state[userID] = role
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><result><status>success</status></result></operation></response>`))
		case strings.Contains(raw, "<delete>"):
			if _, ok := state[userID]; !ok {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><result><status>failure</status><errormessage>user does not exist</errormessage></result></operation></response>`))
				return
			}
			delete(state, userID)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><result><status>success</status></result></operation></response>`))
		case strings.Contains(raw, "<readByQuery>"):
			if r, ok := state[userID]; ok {
				_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><result><status>success</status><data><USERINFO><USERID>` + userID + `</USERID><ROLES><ROLE><ROLEID>` + r + `</ROLEID></ROLE></ROLES></USERINFO></data></result></operation></response>`))
				return
			}
			_, _ = w.Write([]byte(`<?xml version="1.0"?><response><operation><result><status>success</status><data></data></result></operation></response>`))
		default:
			t.Errorf("unexpected XML body: %s", raw)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := sageValidConfig()
	secrets := sageValidSecrets()
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
	if len(ents) != 1 || ents[0].Role != role {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, role)
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

func TestSageIntacctConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		sageValidConfig(), sageValidSecrets(),
		access.AccessGrant{UserExternalID: "bob", ResourceExternalID: "audit_user"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
