package expensify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func expensifyValidConfig() map[string]interface{} {
	return map[string]interface{}{"policy_id": "POLICY123"}
}
func expensifyValidSecrets() map[string]interface{} {
	return map[string]interface{}{
		"partner_user_id":     "partner-AAAA",
		"partner_user_secret": "secret-BBBB",
	}
}

func TestExpensifyConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const role = "user"

	var mu sync.Mutex
	state := map[string]string{} // email -> role
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		jobRaw := r.PostFormValue("requestJobDescription")
		if jobRaw == "" {
			t.Fatalf("missing requestJobDescription")
		}
		var job map[string]interface{}
		if err := json.Unmarshal([]byte(jobRaw), &job); err != nil {
			t.Fatalf("decode job: %v", err)
		}
		input, _ := job["inputSettings"].(map[string]interface{})
		jobType, _ := input["type"].(string)
		mu.Lock()
		defer mu.Unlock()
		switch jobType {
		case "employeesCreate":
			employees, _ := input["employees"].([]interface{})
			for _, e := range employees {
				em, _ := e.(map[string]interface{})
				addr, _ := em["email"].(string)
				if _, ok := state[strings.ToLower(addr)]; ok {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"responseCode":401,"responseMessage":"already a member"}`))
					return
				}
				state[strings.ToLower(addr)] = strings.TrimSpace(em["role"].(string))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"responseCode":200}`))
		case "employeesRemove":
			employees, _ := input["employees"].([]interface{})
			for _, e := range employees {
				em, _ := e.(map[string]interface{})
				addr, _ := em["email"].(string)
				if _, ok := state[strings.ToLower(addr)]; !ok {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"responseCode":404,"responseMessage":"not a member"}`))
					return
				}
				delete(state, strings.ToLower(addr))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"responseCode":200}`))
		case "policyList":
			employees := []map[string]string{}
			for em, r := range state {
				employees = append(employees, map[string]string{"email": em, "role": r})
			}
			payload := map[string]interface{}{
				"responseCode": 200,
				"policyList": []map[string]interface{}{
					{"id": "POLICY123", "employees": employees},
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
		default:
			t.Errorf("unexpected job type %q", jobType)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := expensifyValidConfig()
	secrets := expensifyValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: role}

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
	if len(ents) != 1 || ents[0].Role != role {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, role)
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

func TestExpensifyConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		expensifyValidConfig(), expensifyValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "user"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
