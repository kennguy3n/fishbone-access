package brex

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	const userID = "user-42"
	const roleID = "role-9"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		putPath := "/v2/users/" + userID + "/roles/" + roleID
		listPath := "/v2/users/" + userID + "/roles"
		switch {
		case r.Method == http.MethodPut && r.URL.Path == putPath:
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already assigned"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == putPath:
			if !isMember {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not assigned"}`))
				return
			}
			isMember = false
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == listPath:
			data := []map[string]interface{}{}
			if isMember {
				data = append(data, map[string]interface{}{
					"id":   roleID,
					"name": "Power User",
				})
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
	cfg := validConfig()
	secrets := validSecrets()
	grant := access.AccessGrant{UserExternalID: userID, ResourceExternalID: roleID}

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
	if ents[0].ResourceExternalID != roleID {
		t.Fatalf("ents[0].ResourceExternalID = %q, want %q (must round-trip grant.ResourceExternalID)",
			ents[0].ResourceExternalID, roleID)
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

// TestListEntitlements_PreservesIDRepresentation guards decodeFlexibleID:
// a large numeric role id must round-trip exactly (no float64 precision
// loss / scientific notation), and a bare-array response with a string id
// must be unquoted correctly.
func TestListEntitlements_PreservesIDRepresentation(t *testing.T) {
	const userID = "user-1"
	// 9007199254740993 == 2^53 + 1, which float64 cannot represent exactly.
	const bigNumericID = "9007199254740993"
	cases := []struct {
		name   string
		body   string
		wantID string
	}{
		{
			name:   "large numeric id in envelope",
			body:   `{"data":[{"id":` + bigNumericID + `,"name":"Admin"}]}`,
			wantID: bigNumericID,
		},
		{
			name:   "string id in bare array",
			body:   `[{"id":"ADMIN","name":"Admin"}]`,
			wantID: "ADMIN",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/users/"+userID+"/roles" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.httpClient = func() httpDoer { return srv.Client() }
			ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), userID)
			if err != nil {
				t.Fatalf("ListEntitlements: %v", err)
			}
			if len(ents) != 1 {
				t.Fatalf("ents len = %d, want 1: %#v", len(ents), ents)
			}
			if ents[0].ResourceExternalID != tc.wantID {
				t.Fatalf("ResourceExternalID = %q, want %q", ents[0].ResourceExternalID, tc.wantID)
			}
		})
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
		access.AccessGrant{UserExternalID: "user-42", ResourceExternalID: "role-9"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
