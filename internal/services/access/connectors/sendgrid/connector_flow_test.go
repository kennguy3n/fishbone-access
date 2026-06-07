package sendgrid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func sendgridValidConfig() map[string]interface{} { return map[string]interface{}{} }
func sendgridValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "SG.AAAA-test-token"}
}

func TestSendgridConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"
	const scope = "mail.send"

	var mu sync.Mutex
	state := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth missing")
		}
		teammates := "/v3/teammates"
		teammate := teammates + "/" + email
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == teammates:
			if state != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"errors":[{"message":"teammate already exists"}]}`))
				return
			}
			state = scope
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"username":"` + email + `","email":"` + email + `","scopes":["` + scope + `"]}`))
		case r.Method == http.MethodDelete && r.URL.Path == teammate:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			state = ""
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == teammate:
			if state == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"username": email, "email": email, "scopes": []string{state},
			})
		case r.Method == http.MethodGet && r.URL.Path == teammates+"/pending":
			// No pending invites in this lifecycle (the teammate username
			// equals the email here), so revoke after the teammate is gone
			// resolves to idempotent success.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": []interface{}{}})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := sendgridValidConfig()
	secrets := sendgridValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: scope}

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
	if len(ents) != 1 || ents[0].ResourceExternalID != scope || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v, want 1 with scope=%s source=direct", ents, scope)
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

// When a grant references a teammate that was invited by email but has not
// accepted yet, the username-keyed DELETE /v3/teammates/{email} 404s and
// RevokeAccess must fall back to deleting the pending invite by email.
func TestRevokeAccess_PendingInviteByEmail(t *testing.T) {
	const email = "bob@example.com"
	const token = "pend-tok-123"
	var deletedPending bool
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == "/v3/teammates/"+email:
			// No active teammate with this username yet.
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/v3/teammates/pending":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []map[string]interface{}{
					{"email": "someone-else@example.com", "token": "other"},
					{"email": email, "token": token},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v3/teammates/pending/"+token:
			deletedPending = true
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
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: "mail.send"}
	if err := c.RevokeAccess(context.Background(), sendgridValidConfig(), sendgridValidSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !deletedPending {
		t.Fatal("expected pending invite to be deleted by token")
	}
}

// Revoke is idempotent when the user is neither an active teammate nor a
// pending invite (already removed): the username DELETE 404s and the pending
// list contains no match, so RevokeAccess returns nil.
func TestRevokeAccess_NoActiveOrPendingIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v3/teammates/") && r.URL.Path != "/v3/teammates/pending":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/v3/teammates/pending":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": []interface{}{}})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	grant := access.AccessGrant{UserExternalID: "ghost@example.com", ResourceExternalID: "mail.send"}
	if err := c.RevokeAccess(context.Background(), sendgridValidConfig(), sendgridValidSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess (idempotent): %v", err)
	}
}

// When the matching pending invite lives beyond the first page, revoke must
// paginate the pending list (offset/limit) to find and delete it rather than
// stopping after page 0.
func TestRevokeAccess_PendingInviteOnLaterPage(t *testing.T) {
	const email = "late@example.com"
	const token = "pend-tok-late"
	const pageSize = sendgridPendingPageSize
	var deletedPending bool
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == "/v3/teammates/"+email:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/v3/teammates/pending":
			offset := 0
			_, _ = fmt.Sscanf(r.URL.Query().Get("offset"), "%d", &offset)
			result := make([]map[string]interface{}, 0, pageSize)
			if offset == 0 {
				// A full first page that does NOT contain the target,
				// forcing the lookup to request the next page.
				for i := 0; i < pageSize; i++ {
					result = append(result, map[string]interface{}{
						"email": fmt.Sprintf("filler-%d@example.com", i),
						"token": fmt.Sprintf("tok-%d", i),
					})
				}
			} else {
				result = append(result, map[string]interface{}{"email": email, "token": token})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": result})
		case r.Method == http.MethodDelete && r.URL.Path == "/v3/teammates/pending/"+token:
			deletedPending = true
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
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: "mail.send"}
	if err := c.RevokeAccess(context.Background(), sendgridValidConfig(), sendgridValidSecrets(), grant); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !deletedPending {
		t.Fatal("expected pending invite on later page to be deleted by token")
	}
}

func TestSendgridConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		sendgridValidConfig(), sendgridValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", ResourceExternalID: "mail.send"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
