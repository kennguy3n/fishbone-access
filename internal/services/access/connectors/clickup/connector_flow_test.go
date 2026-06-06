package clickup

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

func TestConnectorFlow_FullLifecycle(t *testing.T) {
	var member atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/api/v2/list/list-1/member"):
			if member.Load() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			member.Store(true)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/api/v2/list/list-1/member/42"):
			if !member.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			member.Store(false)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/api/v2/team/team-1/member"):
			if member.Load() {
				_, _ = w.Write([]byte(`{"members":[{"user":{"id":42,"email":"a@b.com","role":3}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"members":[]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/api/v2/team/team-1"):
			_, _ = w.Write([]byte(`{"team":{"id":"team-1"}}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	grant := access.AccessGrant{UserExternalID: "42", ResourceExternalID: "list-1"}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "42")
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
	ents, _ = c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "42")
	if len(ents) != 0 {
		t.Fatalf("got %d after revoke", len(ents))
	}
}

func TestConnectorFlow_ProvisionFailsOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "42", ResourceExternalID: "list-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403; got %v", err)
	}
}

// TestProvisionRevoke_TrimsWhitespaceExternalID guards that grant IDs with
// stray whitespace are trimmed before use. Validation already trims when
// checking for emptiness, so a padded ID like " 42 " passes validation; the
// connector must then (a) parse it as the numeric user_id 42 on Provision
// rather than failing strconv.ParseInt with a misleading "must be numeric"
// error, and (b) hit the literal /member/42 path on Revoke rather than the
// %20-escaped /member/%2042%20 (which would 404 and be silently swallowed as
// an idempotent no-op — a false "revoked").
func TestProvisionRevoke_TrimsWhitespaceExternalID(t *testing.T) {
	var gotUserID float64
	var deletePath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var payload map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if v, ok := payload["user_id"].(float64); ok {
				gotUserID = v
			}
			_, _ = w.Write([]byte(`{}`))
		case http.MethodDelete:
			deletePath = r.URL.Path
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	grant := access.AccessGrant{UserExternalID: " 42 ", ResourceExternalID: " list-1 "}

	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if gotUserID != 42 {
		t.Fatalf("POST user_id = %v, want 42 (whitespace must be trimmed before ParseInt)", gotUserID)
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if deletePath != "/api/v2/list/list-1/member/42" {
		t.Fatalf("DELETE path = %q, want /api/v2/list/list-1/member/42 (IDs must be trimmed before PathEscape)", deletePath)
	}
}
