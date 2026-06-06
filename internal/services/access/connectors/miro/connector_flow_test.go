package miro

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle exercises a Miro member-ID
// UserExternalID end-to-end. ProvisionAccess must resolve the email via
// GET /orgs/{org}/members/{id} before POSTing to /teams/.../members,
// then RevokeAccess uses the member ID directly in the URL.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var inTeam atomic.Bool
	const memberID = "u1"
	const memberEmail = "alice@example.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/orgs/ORG/members/u1"):
			_, _ = w.Write([]byte(`{"id":"u1","email":"alice@example.com","role":"member"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs/ORG/teams/team-1/members"):
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), memberEmail) {
				t.Errorf("POST body must carry resolved email; got %s", string(b))
			}
			if inTeam.Load() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			inTeam.Store(true)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/orgs/ORG/teams/team-1/members/u1"):
			if !inTeam.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			inTeam.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/orgs/ORG/members/u1/teams"):
			if inTeam.Load() {
				_, _ = w.Write([]byte(`{"data":[{"id":"team-1","name":"X","role":"member"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/orgs/ORG"):
			_, _ = w.Write([]byte(`{"id":"ORG"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: memberID, ResourceExternalID: "team-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), memberID)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("got 0 after provision")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), memberID)
	if len(ents) != 0 {
		t.Fatalf("got %d after revoke", len(ents))
	}
}

// TestConnectorFlow_FullLifecycle_EmailForm exercises the same lifecycle
// using an email address as UserExternalID. ProvisionAccess sends the
// email directly; RevokeAccess and ListEntitlements must paginate the
// org-members listing to resolve the email back to a member ID and use
// that ID in the URL path.
func TestConnectorFlow_FullLifecycle_EmailForm(t *testing.T) {
	var inTeam atomic.Bool
	const memberID = "u1"
	const memberEmail = "alice@example.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/orgs/ORG/members") && r.URL.Query().Get("limit") != "":
			payload := map[string]interface{}{
				"data": []map[string]string{{"id": memberID, "email": memberEmail, "role": "member"}},
			}
			_ = json.NewEncoder(w).Encode(payload)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/orgs/ORG/teams/team-1/members"):
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), memberEmail) {
				t.Errorf("POST body must carry email; got %s", string(b))
			}
			if inTeam.Load() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			inTeam.Store(true)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/orgs/ORG/teams/team-1/members/"+memberID):
			if !inTeam.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			inTeam.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/orgs/ORG/members/"+memberID+"/teams"):
			if inTeam.Load() {
				_, _ = w.Write([]byte(`{"data":[{"id":"team-1","name":"X","role":"member"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/orgs/ORG"):
			_, _ = w.Write([]byte(`{"id":"ORG"}`))
		default:
			t.Logf("unexpected request: %s %s", r.Method, r.URL.String())
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: memberEmail, ResourceExternalID: "team-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), memberEmail)
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("got 0 after provision")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "a@b.com", ResourceExternalID: "team-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}
