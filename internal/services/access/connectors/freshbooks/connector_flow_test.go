package freshbooks

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
	const userID = "stf-7"
	const resID = "managed_user"
	const accountID = "abcDEF"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		staffPath := "/accounting/account/" + accountID + "/users/staffs/" + userID
		listPath := "/accounting/account/" + accountID + "/users/staffs"
		switch {
		case r.Method == http.MethodPut && r.URL.Path == staffPath:
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			raw, _ := io.ReadAll(r.Body)
			var p struct {
				Staff struct {
					Role     string `json:"role"`
					VisState int    `json:"vis_state"`
				} `json:"staff"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Errorf("decode staff PUT body: %v (body=%q)", err, string(raw))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if strings.TrimSpace(p.Staff.Role) != resID {
				t.Errorf("PUT staff.role = %q, want %q", p.Staff.Role, resID)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if p.Staff.VisState == 1 {
				// soft-delete (revoke)
				if !isMember {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				isMember = false
				w.WriteHeader(http.StatusOK)
				return
			}
			// role assignment (provision)
			if isMember {
				w.WriteHeader(http.StatusConflict)
				return
			}
			isMember = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			staff := []map[string]interface{}{}
			if isMember {
				staff = append(staff, map[string]interface{}{"id": userID, "role": resID})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"response": map[string]interface{}{
					"result": map[string]interface{}{"staff": staff},
				},
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
	cfg := validConfig()
	secrets := validSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: resID}

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
	if len(ents) != 1 {
		t.Fatalf("ents len = %d, want 1: %#v", len(ents), ents)
	}
	if ents[0].ResourceExternalID != resID {
		t.Fatalf("ents[0].ResourceExternalID = %q, want %q (must round-trip grant.ResourceExternalID)",
			ents[0].ResourceExternalID, resID)
	}
	if ents[0].Role != resID {
		t.Fatalf("ents[0].Role = %q, want %q", ents[0].Role, resID)
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
		validConfig(),
		validSecrets(),
		access.AccessGrant{UserExternalID: "stf-7", ResourceExternalID: "managed_user"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
