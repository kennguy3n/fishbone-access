package slack_enterprise

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

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "u-1"
	const groupID = "g-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/scim/v2/Users/"+userID:
			body, _ := io.ReadAll(r.Body)
			var patch struct {
				Operations []struct {
					Op   string `json:"op"`
					Path string `json:"path"`
				} `json:"Operations"`
			}
			_ = json.Unmarshal(body, &patch)
			if len(patch.Operations) == 0 {
				t.Errorf("no patch ops in %s", string(body))
			}
			op := patch.Operations[0].Op
			switch op {
			case "add":
				if isMember {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"detail":"already member"}`))
					return
				}
				isMember = true
				w.WriteHeader(http.StatusOK)
			case "remove":
				if !isMember {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				isMember = false
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected op %q", op)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/scim/v2/Users/"+userID:
			groups := []map[string]string{}
			if isMember {
				groups = append(groups, map[string]string{"value": groupID, "display": groupID})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     userID,
				"active": true,
				"groups": groups,
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
	cfg := map[string]interface{}{}
	secrets := map[string]interface{}{"token": "tok"}
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: groupID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != groupID {
		t.Fatalf("ents = %#v", ents)
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

func TestConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "g-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
