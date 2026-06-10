package zoom

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

// TestConnectorFlow_FullLifecycle covers Validate → ProvisionAccess
// (POST /groups/{g}/members) → ListEntitlements (GET /users/{u}/groups)
// → RevokeAccess (DELETE /groups/{g}/members/{u}) using a single mock
// keyed on a `member` flag.
func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var member atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/groups/g-1/members"):
			// Assert the body shape the live Zoom API requires:
			// {"members":[{"id":"u-1"}]}. A flat {"id":"u-1"} body (the
			// pre-fix bug) decodes to an empty members slice and is rejected
			// here, so the regression can never silently reappear.
			var payload struct {
				Members []struct {
					ID string `json:"id"`
				} `json:"members"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			if len(payload.Members) != 1 || payload.Members[0].ID != "u-1" {
				http.Error(w, "members array required", http.StatusBadRequest)
				return
			}
			// First add → 201. A repeat add for an existing member returns
			// 409, the same way Zoom does, so the loop below also exercises
			// ProvisionAccess's idempotent 409/"already exists" no-op path.
			if member.Swap(true) {
				http.Error(w, `{"code":409,"message":"Member already exists"}`, http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/groups/g-1/members/u-1"):
			// First delete → 204. A repeat delete of an absent member returns
			// 404, like Zoom, so the loop below also exercises RevokeAccess's
			// idempotent not-found no-op path.
			if !member.Swap(false) {
				http.Error(w, `{"code":404,"message":"Member not found"}`, http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/users/u-1/groups"):
			if member.Load() {
				_, _ = w.Write([]byte(`{"groups":[{"id":"g-1","name":"dev"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"groups":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "u-1", ResourceExternalID: "g-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
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
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if len(ents) != 0 {
		t.Fatalf("ListEntitlements after revoke: got %d, want 0", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u-1", ResourceExternalID: "g-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ProvisionAccess: want 403, got %v", err)
	}
}
