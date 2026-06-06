package linode

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func linodeValidConfig() map[string]interface{} { return map[string]interface{}{} }
func linodeValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "linode-token-AAAA"}
}

func TestLinodeConnectorFlow_FullLifecycle(t *testing.T) {
	const username = "alice"
	const role = "restricted"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v4/account/users":
			// Linode requires a valid username (no '@') and a separate,
			// valid email — the connector must not reuse the username as
			// the email.
			var probe struct {
				Username string `json:"username"`
				Email    string `json:"email"`
			}
			if err := json.NewDecoder(r.Body).Decode(&probe); err != nil {
				t.Errorf("decode provision body: %v", err)
			}
			if probe.Username != username {
				t.Errorf("provision username = %q; want %q", probe.Username, username)
			}
			if probe.Email != "alice@example.com" {
				t.Errorf("provision email = %q; want alice@example.com", probe.Email)
			}
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"reason":"already exists"}]}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v4/account/users/"+username:
			if !isMember {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			isMember = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v4/account/users":
			data := []map[string]interface{}{}
			if isMember {
				data = append(data, map[string]interface{}{
					"username":   username,
					"email":      "alice@example.com",
					"restricted": true,
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
	cfg := linodeValidConfig()
	secrets := linodeValidSecrets()
	grant := access.AccessGrant{
		UserExternalID:     username,
		ResourceExternalID: role,
		Scope:              map[string]interface{}{"email": "alice@example.com"},
	}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, username)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != role {
		t.Fatalf("ents = %#v, want 1 with role=%s", ents, role)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, username)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
	}
}

func TestLinodeConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		linodeValidConfig(), linodeValidSecrets(),
		access.AccessGrant{
			UserExternalID:     "alice",
			ResourceExternalID: "restricted",
			Scope:              map[string]interface{}{"email": "alice@example.com"},
		})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

// TestLinodeProvision_EmailResolution covers the username/email derivation
// for the create-user body: an email must be supplied (via Scope or an
// email-form ExternalID) and is never just the bare username.
func TestLinodeProvision_EmailResolution(t *testing.T) {
	// Bare username with no email anywhere: must fail loud rather than
	// POST an invalid email equal to the username.
	c := New()
	c.urlOverride = "http://127.0.0.1:0"
	c.httpClient = func() httpDoer { return http.DefaultClient }
	err := c.ProvisionAccess(context.Background(), linodeValidConfig(), linodeValidSecrets(),
		access.AccessGrant{UserExternalID: "bob", ResourceExternalID: "restricted"})
	if err == nil || !strings.Contains(err.Error(), "email is required") {
		t.Fatalf("bare-username err = %v; want email-required error", err)
	}

	// Email-form ExternalID: username derived from the local part, email
	// taken from the identifier.
	var gotUser, gotEmail string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var probe struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&probe)
		gotUser, gotEmail = probe.Username, probe.Email
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c2 := New()
	c2.urlOverride = srv.URL
	c2.httpClient = func() httpDoer { return srv.Client() }
	if err := c2.ProvisionAccess(context.Background(), linodeValidConfig(), linodeValidSecrets(),
		access.AccessGrant{UserExternalID: "carol@example.com", ResourceExternalID: "unrestricted"}); err != nil {
		t.Fatalf("email-form provision: %v", err)
	}
	if gotUser != "carol" || gotEmail != "carol@example.com" {
		t.Fatalf("derived (username=%q,email=%q); want (carol, carol@example.com)", gotUser, gotEmail)
	}
}
