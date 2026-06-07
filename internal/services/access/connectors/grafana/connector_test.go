package grafana

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"base_url": "https://grafana.acme.com"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "grfAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{"username": "u", "password": "p"}); err != nil {
		t.Fatalf("Validate basic: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing base_url")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing creds")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_PaginatesUsers(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth")
		}
		if r.URL.Path != "/api/org/users" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body := []map[string]interface{}{
			{"userId": 1, "email": "a@x.com", "login": "alice", "name": "Alice", "role": "Admin", "isDisabled": false},
			{"userId": 2, "email": "b@x.com", "login": "bob", "name": "", "role": "Viewer", "isDisabled": true},
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d; want 1 (single-page API)", calls)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if got[1].Status != "disabled" || got[1].DisplayName != "bob" {
		t.Errorf("user2 = %+v", got[1])
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v; want 403", err)
	}
}

// TestSync_ExternalIDReconcilesWithRevoke locks the fix for the
// identity-format mismatch: SyncIdentities must emit the login (the
// loginOrEmail key findGrafanaUserID matches on), NOT the numeric userId.
// Emitting the numeric userId silently broke revokes (the login/email
// lookup never matched, so RevokeAccess returned nil without a DELETE).
func TestSync_ExternalIDReconcilesWithRevoke(t *testing.T) {
	const login = "ada"
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/org/users":
			b, _ := json.Marshal([]map[string]interface{}{
				{"userId": 42, "email": "ada@x.com", "login": login, "name": "Ada", "role": "Editor"},
			})
			_, _ = w.Write(b)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/org/users/42":
			deleted = true
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

	var synced []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		synced = append(synced, b...)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(synced) != 1 || synced[0].ExternalID != login {
		t.Fatalf("ExternalID = %q, want %q", synced[0].ExternalID, login)
	}
	// Feed the synced ExternalID straight back into RevokeAccess — it must
	// resolve the numeric userId and issue the DELETE.
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(),
		access.AccessGrant{UserExternalID: synced[0].ExternalID, ResourceExternalID: "Editor"}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !deleted {
		t.Fatal("RevokeAccess did not issue DELETE — synced ExternalID failed to reconcile")
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("token_short = %q", short)
	}
}
