package msteams

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorFlow_FullLifecycle drives the MS Teams connector
// through POST /teams/{team}/members → GET /teams/{team}/members
// (membership lookup) → DELETE /teams/{team}/members/{membershipID},
// and the GET /users/{user}/joinedTeams read for ListEntitlements.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var inTeam atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/teams/team-1/members"):
			inTeam.Store(true)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"membership-1","userId":"user-1","roles":["member"]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/teams/team-1/members"):
			if inTeam.Load() {
				_, _ = w.Write([]byte(`{"value":[{"id":"membership-1","userId":"user-1","roles":["member"]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"value":[]}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/teams/team-1/members/membership-1"):
			inTeam.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/users/user-1/joinedTeams"):
			if inTeam.Load() {
				_, _ = w.Write([]byte(`{"value":[{"id":"team-1","displayName":"Eng"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"value":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "user-1", ResourceExternalID: "team-1", Role: "member"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) == 0 {
		t.Fatalf("ListEntitlements after provision: got 0, want >=1")
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "user-1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied"}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "user-1", ResourceExternalID: "team-1", Role: "member",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ProvisionAccess: want 403, got %v", err)
	}
}

// TestProvisionAccess_EscapesODataSingleQuote verifies that a UserExternalID
// containing a single quote (a valid UPN such as o'brien@contoso.com) is
// escaped per OData rules (doubled quote) inside the user@odata.bind literal,
// rather than producing a syntactically broken /users('o'brien@...') value.
func TestProvisionAccess_EscapesODataSingleQuote(t *testing.T) {
	const upn = "o'brien@contoso.com"
	var gotBind string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/members") {
			var payload struct {
				Bind string `json:"user@odata.bind"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			gotBind = payload.Bind
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"membership-1"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: upn, ResourceExternalID: "team-1", Role: "member"}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	want := srv.URL + "/users('o''brien@contoso.com')"
	if gotBind != want {
		t.Fatalf("user@odata.bind = %q; want %q (single quote must be OData-escaped as '')", gotBind, want)
	}
}
