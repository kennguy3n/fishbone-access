package gemini

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func geminiValidConfig() map[string]interface{} {
	return map[string]interface{}{"project_id": "shieldnet360-prod"}
}
func geminiValidSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "ya29AAAA1234bbbbCCCC"}
}

// TestGeminiConnectorFlow_FullLifecycle exercises the canonical
// Validate → Provision×2 → List ≥1 → Revoke×2 → List 0 sequence against
// a mock Cloud Resource Manager IAM API. The mock tracks policy state in
// memory so the test asserts both the network contract and the
// idempotency invariants documented on the connector.
func TestGeminiConnectorFlow_FullLifecycle(t *testing.T) {
	const email = "alice@example.com"

	var mu sync.Mutex
	policy := geminiPolicy{Etag: "BwAAAAAAA=", Bindings: nil}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/projects/shieldnet360-prod:getIamPolicy":
			if r.Method != http.MethodPost {
				t.Errorf("getIamPolicy method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(policy)
		case "/v1/projects/shieldnet360-prod:setIamPolicy":
			if r.Method != http.MethodPost {
				t.Errorf("setIamPolicy method = %s", r.Method)
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var req geminiSetIamPolicyRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("decode setIamPolicy body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			policy = req.Policy
			_ = json.NewEncoder(w).Encode(policy)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	cfg := geminiValidConfig()
	secrets := geminiValidSecrets()
	grant := access.AccessGrant{UserExternalID: email, ResourceExternalID: defaultGeminiRole, Role: defaultGeminiRole}

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
	if len(ents) != 1 || ents[0].Role != defaultGeminiRole || ents[0].Source != "direct" {
		t.Fatalf("ents = %#v; want 1 binding with role %s source direct", ents, defaultGeminiRole)
	}
	if ents[0].ResourceExternalID != "projects/shieldnet360-prod" {
		t.Errorf("ResourceExternalID = %q", ents[0].ResourceExternalID)
	}

	// Provision idempotency check: policy should hold exactly one member.
	mu.Lock()
	gotMembers := 0
	for _, b := range policy.Bindings {
		if b.Role == defaultGeminiRole {
			gotMembers = len(b.Members)
		}
	}
	mu.Unlock()
	if gotMembers != 1 {
		t.Fatalf("provision idempotency broken: members for %s = %d", defaultGeminiRole, gotMembers)
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
		t.Fatalf("expected empty entitlements, got %#v", ents)
	}
}

// TestGeminiConnectorFlow_ProvisionForbiddenFailure asserts the 403 path
// surfaces upstream so callers can distinguish hard auth failures from
// idempotent no-ops.
func TestGeminiConnectorFlow_ProvisionForbiddenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"permission denied"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		geminiValidConfig(), geminiValidSecrets(),
		access.AccessGrant{UserExternalID: "alice@example.com", Role: defaultGeminiRole})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v; want 403", err)
	}
}

// TestGeminiConnectorFlow_PreservesPrincipalPrefix locks the documented
// behaviour that already-prefixed members (serviceAccount:, group:, etc.)
// are forwarded verbatim instead of being re-prefixed with `user:`.
func TestGeminiConnectorFlow_PreservesPrincipalPrefix(t *testing.T) {
	cases := map[string]string{
		"alice@example.com":        "user:alice@example.com",
		"user:bob@example.com":     "user:bob@example.com",
		"serviceAccount:svc@x.iam": "serviceAccount:svc@x.iam",
		"group:eng@example.com":    "group:eng@example.com",
		"domain:example.com":       "domain:example.com",
	}
	for in, want := range cases {
		if got := principal(in); got != want {
			t.Errorf("principal(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestGeminiConnectorFlow_RejectsEmptyUser ensures the connector rejects
// empty UserExternalIDs before issuing any network calls.
func TestGeminiConnectorFlow_RejectsEmptyUser(t *testing.T) {
	c := New()
	c.urlOverride = "http://127.0.0.1:1" // never reached
	c.httpClient = func() httpDoer { return &http.Client{} }
	cfg := geminiValidConfig()
	secrets := geminiValidSecrets()
	if err := c.ProvisionAccess(context.Background(), cfg, secrets, access.AccessGrant{}); err == nil {
		t.Error("ProvisionAccess: expected error for empty UserExternalID")
	}
	if err := c.RevokeAccess(context.Background(), cfg, secrets, access.AccessGrant{}); err == nil {
		t.Error("RevokeAccess: expected error for empty UserExternalID")
	}
	if _, err := c.ListEntitlements(context.Background(), cfg, secrets, ""); err == nil {
		t.Error("ListEntitlements: expected error for empty externalUserID")
	}
}
