package gcp

import (
	"context"
	"errors"
	"io"
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

const fakeServiceAccountJSON = `{
  "type": "service_account",
  "project_id": "uney-prod",
  "private_key_id": "key-1",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
  "client_email": "ztna@uney-prod.iam.gserviceaccount.com",
  "client_id": "12345"
}`

func validConfig() map[string]interface{} { return map[string]interface{}{"project_id": "uney-prod"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"service_account_json": fakeServiceAccountJSON}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMalformedKey(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{"service_account_json": "{}"}); err == nil {
		t.Error("missing private_key marker: want error")
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

func TestConnect_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"projectId":"uney-prod","name":"projects/uney-prod"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "fake-token", nil }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v", err)
	}
}

func TestSync_FlattensIamPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, ":getIamPolicy") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"bindings":[
			{"role":"roles/owner","members":["user:alice@uney.com","serviceAccount:bot@uney.iam.gserviceaccount.com"]},
			{"role":"roles/viewer","members":["user:alice@uney.com","group:eng@uney.com","domain:partner.com"]}
		]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d; want 3 (alice, bot, group eng); got = %+v", len(got), got)
	}
	types := map[access.IdentityType]int{}
	for _, id := range got {
		types[id.Type]++
	}
	if types[access.IdentityTypeServiceAccount] != 1 || types[access.IdentityTypeGroup] != 1 || types[access.IdentityTypeUser] != 1 {
		t.Errorf("type counts = %+v", types)
	}
}

func TestGetCredentialsMetadata_ExtractsClientEmail(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md["client_email"] != "ztna@uney-prod.iam.gserviceaccount.com" {
		t.Errorf("client_email = %v", md["client_email"])
	}
}

func TestProvisionAccess_AddsBindingViaSetIamPolicy(t *testing.T) {
	var setBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[{"role":"roles/viewer","members":["user:bob@example.com"]}]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			setBody = readAll(r)
			_, _ = w.Write([]byte(`{"etag":"BwYY","bindings":[]}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/editor",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if !strings.Contains(string(setBody), `"role":"roles/editor"`) || !strings.Contains(string(setBody), "user:alice@example.com") {
		t.Fatalf("setIamPolicy body = %s", string(setBody))
	}
}

func TestProvisionAccess_AlreadyBoundIsNoop(t *testing.T) {
	var setCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[{"role":"roles/viewer","members":["user:alice@example.com"]}]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			setCalls++
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/viewer",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if setCalls != 0 {
		t.Fatalf("setIamPolicy called %d times; want 0", setCalls)
	}
}

func TestProvisionAccess_GetPolicyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/viewer",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403, got %v", err)
	}
}

func TestRevokeAccess_RemovesMember(t *testing.T) {
	var setBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[{"role":"roles/viewer","members":["user:alice@example.com","user:bob@example.com"]}]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			setBody = readAll(r)
			_, _ = w.Write([]byte(`{"etag":"BwYY","bindings":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/viewer",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if strings.Contains(string(setBody), "user:alice@example.com") {
		t.Fatalf("setIamPolicy body still references alice: %s", string(setBody))
	}
	if !strings.Contains(string(setBody), "user:bob@example.com") {
		t.Fatalf("setIamPolicy body missing bob: %s", string(setBody))
	}
}

func TestRevokeAccess_NotMemberIsNoop(t *testing.T) {
	var setCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[{"role":"roles/viewer","members":["user:bob@example.com"]}]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			setCalls++
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/viewer",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if setCalls != 0 {
		t.Fatalf("setIamPolicy called %d times; want 0", setCalls)
	}
}

func TestListEntitlements_FiltersByMember(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[{"role":"roles/viewer","members":["user:alice@example.com"]},{"role":"roles/editor","members":["user:bob@example.com"]},{"role":"roles/admin","members":["user:alice@example.com","user:bob@example.com"]}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	roles := map[string]bool{}
	for _, e := range got {
		if e.ResourceExternalID != "uney-prod" {
			t.Fatalf("ResourceExternalID = %q, want uney-prod", e.ResourceExternalID)
		}
		if e.Source != "direct" {
			t.Fatalf("Source = %q", e.Source)
		}
		roles[e.Role] = true
	}
	if !roles["roles/viewer"] || !roles["roles/admin"] {
		t.Fatalf("roles = %+v", roles)
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com"); err == nil {
		t.Fatal("expected error on 403")
	}
}

func readAll(r *http.Request) []byte {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	return b
}

// TestScopeConstants pins the OAuth2 scopes the connector mints. The write
// scope must be the un-suffixed `cloud-platform` (which is required for
// setIamPolicy); the read scope must be the `.read-only` variant. A
// regression here would cause production ProvisionAccess / RevokeAccess
// calls to 403 against real GCP, while local tests (which bypass OAuth2
// via tokenOverride / httpClient) continue to pass.
func TestScopeConstants(t *testing.T) {
	if cloudPlatformWriteScope != "https://www.googleapis.com/auth/cloud-platform" {
		t.Errorf("cloudPlatformWriteScope = %q; want %q",
			cloudPlatformWriteScope,
			"https://www.googleapis.com/auth/cloud-platform")
	}
	if !strings.HasSuffix(cloudPlatformReadScope, ".read-only") {
		t.Errorf("cloudPlatformReadScope must end in .read-only; got %q", cloudPlatformReadScope)
	}
	if cloudPlatformWriteScope == cloudPlatformReadScope {
		t.Error("write and read scopes must differ")
	}
	if strings.Contains(cloudPlatformWriteScope, ".read-only") {
		t.Errorf("cloudPlatformWriteScope must not be a read-only scope; got %q", cloudPlatformWriteScope)
	}
	// Cloud Identity Groups API requires its own dedicated scope —
	// tokens minted with only cloud-platform.read-only 403 against
	// cloudidentity.googleapis.com.
	if cloudIdentityReadScope != "https://www.googleapis.com/auth/cloud-identity.groups.readonly" {
		t.Errorf("cloudIdentityReadScope = %q; want %q",
			cloudIdentityReadScope,
			"https://www.googleapis.com/auth/cloud-identity.groups.readonly")
	}
	if cloudIdentityReadScope == cloudPlatformReadScope {
		t.Error("cloud-identity scope must differ from cloud-platform.read-only — Cloud Identity rejects the latter")
	}
}

type recordingClient struct {
	inner *http.Client
	calls *int
}

func (r *recordingClient) Do(req *http.Request) (*http.Response, error) {
	*r.calls++
	return r.inner.Do(req)
}

// TestProvisionAccess_UsesWriteClient asserts that ProvisionAccess routes
// through cloudResourceWriteClient (i.e. the httpWriteClient hook) rather
// than the read-only cloudResourceClient. It does so by injecting two
// distinct httpDoers — one for read (httpClient) and one for write
// (httpWriteClient) — and verifying only the write hook was invoked.
func TestProvisionAccess_UsesWriteClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwYY","bindings":[]}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	var readCalls, writeCalls int
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &recordingClient{inner: srv.Client(), calls: &readCalls}, nil
	}
	c.httpWriteClient = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &recordingClient{inner: srv.Client(), calls: &writeCalls}, nil
	}

	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/editor",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if readCalls != 0 {
		t.Errorf("read client invoked %d times; ProvisionAccess must use the write client only", readCalls)
	}
	if writeCalls < 2 {
		t.Errorf("write client invoked %d times; expected >=2 (getIamPolicy + setIamPolicy)", writeCalls)
	}
}

// TestRevokeAccess_UsesWriteClient mirrors the assertion for RevokeAccess.
func TestRevokeAccess_UsesWriteClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[{"role":"roles/viewer","members":["user:alice@example.com"]}]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"BwYY","bindings":[]}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	var readCalls, writeCalls int
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &recordingClient{inner: srv.Client(), calls: &readCalls}, nil
	}
	c.httpWriteClient = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &recordingClient{inner: srv.Client(), calls: &writeCalls}, nil
	}

	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "roles/viewer",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if readCalls != 0 {
		t.Errorf("read client invoked %d times; RevokeAccess must use the write client only", readCalls)
	}
	if writeCalls < 2 {
		t.Errorf("write client invoked %d times; expected >=2 (getIamPolicy + setIamPolicy)", writeCalls)
	}
}

// TestListEntitlements_UsesReadClient asserts that ListEntitlements stays
// on the read-only client (least privilege).
func TestListEntitlements_UsesReadClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"etag":"BwXX","bindings":[{"role":"roles/viewer","members":["user:alice@example.com"]}]}`))
	}))
	t.Cleanup(srv.Close)

	var readCalls, writeCalls int
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &recordingClient{inner: srv.Client(), calls: &readCalls}, nil
	}
	c.httpWriteClient = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &recordingClient{inner: srv.Client(), calls: &writeCalls}, nil
	}

	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice@example.com"); err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if writeCalls != 0 {
		t.Errorf("write client invoked %d times; ListEntitlements must use the read-only client", writeCalls)
	}
	if readCalls < 1 {
		t.Error("read client never invoked")
	}
}
