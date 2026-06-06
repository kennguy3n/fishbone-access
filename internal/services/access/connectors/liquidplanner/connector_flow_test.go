package liquidplanner

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
	const email = "ada@example.com"
	const memberID = 77
	const workspaceID = "12345"
	isMember := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workspaces/"+workspaceID+"/members":
			members := []map[string]interface{}{}
			if isMember {
				members = append(members, map[string]interface{}{
					"id":           memberID,
					"email":        email,
					"access_level": "member",
				})
			}
			_ = json.NewEncoder(w).Encode(members)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/"+workspaceID+"/members":
			if isMember {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"already a member"}`))
				return
			}
			isMember = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/workspaces/"+workspaceID+"/members/"):
			isMember = false
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := map[string]interface{}{"workspace_id": workspaceID}
	secrets := map[string]interface{}{"token": "tok"}
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: workspaceID}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != workspaceID {
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

// TestConnectorFlow_ProvisionWithNumericExternalID guards against regressing
// the bug where ProvisionAccess unconditionally dropped grant.UserExternalID
// into the `email` JSON field. SyncIdentities sets ExternalID to the numeric
// member id, so a numeric identifier for a user that is NOT yet a workspace
// member must produce a clear error and NEVER POST `{"email":"77",...}` to
// the create-member endpoint.
func TestConnectorFlow_ProvisionWithNumericExternalID(t *testing.T) {
	const workspaceID = "12345"
	var postBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workspaces/"+workspaceID+"/members":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/"+workspaceID+"/members":
			b, _ := io.ReadAll(r.Body)
			postBodies = append(postBodies, string(b))
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{"workspace_id": workspaceID},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "77", ResourceExternalID: workspaceID})
	if err == nil {
		t.Fatalf("expected error resolving numeric identifier with no matching member, got nil")
	}
	if !strings.Contains(err.Error(), "provision requires an email") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(postBodies) != 0 {
		t.Fatalf("expected zero POSTs, got %d: %v", len(postBodies), postBodies)
	}
}

// TestConnectorFlow_ProvisionResolvesNumericToEmail verifies that when the
// numeric identifier DOES match an existing member with an email on record,
// ProvisionAccess no-ops (idempotent path) rather than re-POSTing the numeric
// id as an email. Together with the test above this proves the email field
// can never carry a non-email value.
func TestConnectorFlow_ProvisionResolvesNumericToEmail(t *testing.T) {
	const workspaceID = "12345"
	var postBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workspaces/"+workspaceID+"/members":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
				"id":           77,
				"email":        "ada@example.com",
				"access_level": "member",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/"+workspaceID+"/members":
			b, _ := io.ReadAll(r.Body)
			postBodies = append(postBodies, string(b))
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{"workspace_id": workspaceID},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "77", ResourceExternalID: workspaceID}); err != nil {
		t.Fatalf("ProvisionAccess with numeric id of existing member: %v", err)
	}
	if len(postBodies) != 0 {
		t.Fatalf("expected zero POSTs (idempotent on existing member), got %d: %v", len(postBodies), postBodies)
	}
}

// TestConnectorFlow_RevokeSurfacesPreCheckError guards against regressing the
// bug where RevokeAccess returned nil whenever the /members pre-check fetch
// failed with a transient error. A transient lookup failure must NOT be
// interpreted as "user already revoked" — that would silently leave the
// caller believing the user has lost access while they still hold workspace
// membership. We assert that a 5xx on the listing endpoint propagates as an
// error and that no DELETE is attempted (no destructive operation against an
// unknown member id).
func TestConnectorFlow_RevokeSurfacesPreCheckError(t *testing.T) {
	const workspaceID = "12345"
	var deleteCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workspaces/"+workspaceID+"/members":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"backend unavailable"}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/workspaces/"+workspaceID+"/members/"):
			deleteCount++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(),
		map[string]interface{}{"workspace_id": workspaceID},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "ada@example.com", ResourceExternalID: workspaceID})
	if err == nil {
		t.Fatalf("expected revoke pre-check error to propagate, got nil (silent no-op)")
	}
	if !strings.Contains(err.Error(), "revoke pre-check") {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleteCount != 0 {
		t.Fatalf("expected zero DELETEs when pre-check fails, got %d", deleteCount)
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
		map[string]interface{}{"workspace_id": "12345"},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "ada@example.com", ResourceExternalID: "12345"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
