package loom

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
	const email = "ada@example.com"
	const memberID = "mem-42"
	const role = "member"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/members":
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already_member"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/members/"):
			isMember = false
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/members":
			members := []map[string]interface{}{}
			if isMember {
				members = append(members, map[string]interface{}{
					"id":    memberID,
					"email": email,
					"role":  role,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": members,
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
		t.Fatalf("ents = %#v", ents)
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

// TestConnectorFlow_RevokeAndListByMemberID guards the JML path where the
// identifier is the member ID (the ExternalID SyncIdentities exports) rather
// than an email. Revoke must DELETE the member directly and ListEntitlements
// must resolve the role by ID — neither may silently no-op.
func TestConnectorFlow_RevokeAndListByMemberID(t *testing.T) {
	const memberID = "mem-99"
	const email = "grace@example.com"
	const role = "admin"
	var deletedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/members":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": memberID, "email": email, "role": role},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/members/"):
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
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

	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, memberID)
	if err != nil {
		t.Fatalf("ListEntitlements by id: %v", err)
	}
	if len(ents) != 1 || ents[0].Role != role {
		t.Fatalf("ents = %#v", ents)
	}

	grant := access.AccessGrant{UserExternalID: memberID, ResourceExternalID: role}
	if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
		t.Fatalf("RevokeAccess by id: %v", err)
	}
	if deletedPath != "/v1/members/"+memberID {
		t.Fatalf("expected DELETE /v1/members/%s, got %q", memberID, deletedPath)
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
		access.AccessGrant{UserExternalID: "ada@example.com", ResourceExternalID: "member"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
