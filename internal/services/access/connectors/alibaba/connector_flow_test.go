package alibaba

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func alibabaValidConfig() map[string]interface{} { return map[string]interface{}{} }
func alibabaValidSecrets() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id":     "LTAI-AAAA",
		"access_key_secret": "secret-BBBB",
	}
}

func TestAlibabaConnectorFlow_FullLifecycle(t *testing.T) {
	const userName = "alice"
	const policy = "Custom/ECSReadOnly"
	const policyName = "ECSReadOnly"
	attached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse: %v", err)
		}
		action := r.Form.Get("Action")
		if r.Form.Get("Signature") == "" {
			t.Errorf("missing Signature param")
		}
		switch action {
		case "AttachPolicyToUser":
			if attached {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"Code":"EntityAlreadyExist.User.Policy"}`))
				return
			}
			attached = true
			_, _ = w.Write([]byte(`{"RequestId":"abc"}`))
		case "DetachPolicyFromUser":
			if !attached {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"Code":"EntityNotExist.User.Policy"}`))
				return
			}
			attached = false
			_, _ = w.Write([]byte(`{"RequestId":"abc"}`))
		case "ListPoliciesForUser":
			payload := map[string]interface{}{"Policies": map[string]interface{}{"Policy": []map[string]string{}}}
			if attached {
				payload = map[string]interface{}{
					"Policies": map[string]interface{}{
						"Policy": []map[string]string{
							{"PolicyName": policyName, "PolicyType": "Custom"},
						},
					},
				}
			}
			_ = json.NewEncoder(w).Encode(payload)
		default:
			t.Errorf("unexpected action %q", action)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	cfg := alibabaValidConfig()
	secrets := alibabaValidSecrets()
	grant := access.AccessGrant{UserExternalID: userName, ResourceExternalID: policy}

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
	if len(ents) != 1 || ents[0].Role != policyName {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, policyName)
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

func TestAlibabaConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"Code":"NoPermission"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		alibabaValidConfig(), alibabaValidSecrets(),
		access.AccessGrant{UserExternalID: "alice", ResourceExternalID: "Custom/ECSReadOnly"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
