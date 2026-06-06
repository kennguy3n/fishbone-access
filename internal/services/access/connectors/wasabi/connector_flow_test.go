package wasabi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func wasabiValidConfig() map[string]interface{} { return map[string]interface{}{} }
func wasabiValidSecrets() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id":     "AKIATESTAAAA",
		"secret_access_key": "secret-BBBB",
	}
}

func TestWasabiConnectorFlow_FullLifecycle(t *testing.T) {
	const userName = "alice"
	const policyArn = "arn:aws:iam::123456789012:policy/ECSReadOnly"
	attached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Errorf("missing SigV4: %q", r.Header.Get("Authorization"))
		}
		switch r.Form.Get("Action") {
		case "AttachUserPolicy":
			if attached {
				w.WriteHeader(http.StatusConflict)
				_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>EntityAlreadyExists</Code></Error></ErrorResponse>`)
				return
			}
			attached = true
			_, _ = fmt.Fprint(w, `<AttachUserPolicyResponse/>`)
		case "DetachUserPolicy":
			if !attached {
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`)
				return
			}
			attached = false
			_, _ = fmt.Fprint(w, `<DetachUserPolicyResponse/>`)
		case "ListAttachedUserPolicies":
			if !attached {
				_, _ = fmt.Fprint(w, `<ListAttachedUserPoliciesResponse><ListAttachedUserPoliciesResult><AttachedPolicies/></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>`)
				return
			}
			_, _ = fmt.Fprintf(w, `<ListAttachedUserPoliciesResponse><ListAttachedUserPoliciesResult><AttachedPolicies><member><PolicyName>ECSReadOnly</PolicyName><PolicyArn>%s</PolicyArn></member></AttachedPolicies></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>`, policyArn)
		default:
			t.Errorf("unexpected Action %q", r.Form.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := wasabiValidConfig()
	secrets := wasabiValidSecrets()
	grant := access.AccessGrant{UserExternalID: userName, ResourceExternalID: policyArn}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != policyArn {
		t.Fatalf("ents = %#v, want 1 with PolicyArn=%s", ents, policyArn)
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

func TestWasabiConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		wasabiValidConfig(), wasabiValidSecrets(),
		access.AccessGrant{UserExternalID: "alice", ResourceExternalID: "arn:aws:iam::123:policy/X"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
