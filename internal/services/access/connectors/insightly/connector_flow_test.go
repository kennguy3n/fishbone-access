package insightly

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func insightlyValidConfig() map[string]interface{} { return map[string]interface{}{"pod": "na1"} }
func insightlyValidSecrets() map[string]interface{} {
	return map[string]interface{}{"api_key": "key-AAAA"}
}

func TestInsightlyConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "777"
	const permID = "perm-1"
	hasPerm := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("missing basic auth")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v3.1/Permissions":
			if hasPerm {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"Detail":"already exists"}`))
				return
			}
			hasPerm = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v3.1/Permissions/"+permID:
			if !hasPerm {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hasPerm = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v3.1/Permissions":
			permissions := []map[string]interface{}{}
			if hasPerm {
				permissions = append(permissions, map[string]interface{}{
					"PERMISSION_ID":   permID,
					"PERMISSION_NAME": "read",
					"USER_ID":         userID,
				})
			}
			_ = json.NewEncoder(w).Encode(permissions)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := insightlyValidConfig()
	secrets := insightlyValidSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: permID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != permID {
		t.Fatalf("ents = %#v, want 1 with permID=%s", ents, permID)
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

func TestInsightlyConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		insightlyValidConfig(), insightlyValidSecrets(),
		access.AccessGrant{UserExternalID: "777", ResourceExternalID: "perm-1"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
