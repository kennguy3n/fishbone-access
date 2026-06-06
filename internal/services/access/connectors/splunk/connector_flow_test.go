package splunk

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
	const userName = "ada"
	const roleName = "power"
	exists := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("auth header missing: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/services/authentication/users":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "name="+userName) {
				t.Errorf("body = %s", string(body))
			}
			if exists {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"messages":[{"type":"ERROR","text":"User already exists"}]}`))
				return
			}
			exists = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"entry":[{"name":"` + userName + `","content":{"roles":["` + roleName + `"]}}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/services/authentication/users/"+userName:
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"entry": []map[string]interface{}{{
					"name":    userName,
					"content": map[string]interface{}{"roles": []string{roleName}, "email": "ada@example.com"},
				}},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/services/authentication/users/"+userName:
			exists = false
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
	secrets := map[string]interface{}{"token": "tok"}
	cfg := map[string]interface{}{"base_url": srv.URL}
	grant := access.AccessGrant{
		UserExternalID:     userName,
		ResourceExternalID: roleName,
		Scope:              map[string]interface{}{"password": "S3cret!"},
	}

	if err := c.Validate(context.Background(), cfg, secrets); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := c.ProvisionAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("ProvisionAccess[%d]: %v", i, err)
		}
	}
	ents, err := c.ListEntitlements(context.Background(), cfg, secrets, userName)
	if err != nil {
		t.Fatalf("ListEntitlements after provision: %v", err)
	}
	if len(ents) != 1 || ents[0].Role != roleName {
		t.Fatalf("ents = %#v", ents)
	}
	for i := 0; i < 2; i++ {
		if err := c.RevokeAccess(context.Background(), cfg, secrets, grant); err != nil {
			t.Fatalf("RevokeAccess[%d]: %v", i, err)
		}
	}
	ents, err = c.ListEntitlements(context.Background(), cfg, secrets, userName)
	if err != nil {
		t.Fatalf("ListEntitlements after revoke: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("expected empty, got %#v", ents)
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
		map[string]interface{}{"base_url": srv.URL},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "ada", ResourceExternalID: "power"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

// TestConnectorFlow_ProvisionAccessHTMLProxyBodyScrubbed enforces the
// cross-method scrubbing contract for the doRaw() paths in advanced.go
// (ProvisionAccess / RevokeAccess / ListEntitlements). These methods
// don't route through the shared do() because they need to branch on
// status code for transient retry semantics, but they MUST still route
// the error message through formatErrorBody so a reverse proxy's HTML
// 502 body can't leak trace IDs, cookie names, or hostnames.
func TestConnectorFlow_ProvisionAccessHTMLProxyBodyScrubbed(t *testing.T) {
	htmlBody := `<!DOCTYPE html><html><body>` +
		`<p>x-amzn-trace-id: Root=1-secret-trace-id-do-not-log</p>` +
		`<p>set-cookie: AWSALB=secret-cookie-do-not-log</p>` +
		`</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(htmlBody))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(),
		map[string]interface{}{"base_url": srv.URL},
		map[string]interface{}{"token": "tok"},
		access.AccessGrant{UserExternalID: "ada", ResourceExternalID: "power"})
	if err == nil {
		t.Fatal("err = nil; want 502 error")
	}
	msg := err.Error()
	if strings.Contains(msg, "x-amzn-trace-id") ||
		strings.Contains(msg, "secret-trace-id") ||
		strings.Contains(msg, "AWSALB") ||
		strings.Contains(msg, "secret-cookie") {
		t.Errorf("ProvisionAccess error leaked HTML body content: %q", msg)
	}
	if !strings.Contains(msg, "kind=html") {
		t.Errorf("ProvisionAccess error should include 'kind=html' hint; got %q", msg)
	}
}
