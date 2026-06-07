package mixpanel

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

func validConfig() map[string]interface{} { return map[string]interface{}{"organization_id": "12345"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"service_account_user": "svc_AAAA", "service_account_secret": "sec_AAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestBuildPath_OmitsMeSegment is a regression test for the fix that removed the
// stray "/me/" segment from the org-scoped path. Mixpanel's documented app API
// addresses organization resources at /api/app/organizations/{organizationId}/...
// (e.g. GET /api/app/organizations/{organizationId}/service-accounts), not under
// /api/app/me/. Requesting /api/app/me/organizations/{org}/members 404s.
func TestBuildPath_OmitsMeSegment(t *testing.T) {
	got := New().buildPath(Config{OrganizationID: "12345"})
	const want = "/api/app/organizations/12345/members"
	if got != want {
		t.Fatalf("buildPath = %q; want %q", got, want)
	}
	if strings.Contains(got, "/me/") {
		t.Fatalf("buildPath %q must not contain the /me/ segment", got)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing service account creds")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing org id")
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("expected Basic auth")
		}
		if r.URL.Path != "/api/app/organizations/12345/members" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body := map[string]interface{}{"members": []map[string]interface{}{
			{"id": 1, "name": "Alice", "email": "a@x.com", "role": "owner"},
			{"id": 2, "name": "Bob", "email": "b@x.com", "role": "member"},
		}}
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
	if len(got) != 2 || calls != 1 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	c := New()
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	got, _ := md["secret_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "1234bbbb") {
		t.Errorf("redaction failed: %q", got)
	}
	// user_short is derived from the 8-char service_account_user "svc_AAAA";
	// shortToken must redact it rather than echo the raw value (regression for
	// the len<=8 full-credential leak).
	user, _ := md["user_short"].(string)
	if strings.Contains(user, "svc_AAAA") {
		t.Errorf("user_short leaked raw value: %q", user)
	}
}
