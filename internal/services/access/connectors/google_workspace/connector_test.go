package google_workspace

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// noNetworkRoundTripper fails any HTTP attempt. Used to prove a method does
// not perform network I/O.
type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted from a no-network test path")
}

// makeServiceAccountKeyJSON builds a synthetic but well-formed service-account
// key JSON. The PEM key is real (so any consumer that JWT-signs against it
// will not crash) but the file points at an invented project / email.
func makeServiceAccountKeyJSON(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(key, t)})

	payload := map[string]interface{}{
		"type":           "service_account",
		"project_id":     "proj-test",
		"private_key_id": "kid-1",
		"private_key":    string(pemBytes),
		"client_email":   "svc@proj-test.iam.gserviceaccount.com",
		"client_id":      "999",
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func pkcs8(k *rsa.PrivateKey, t *testing.T) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return b
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{
		"domain":      "example.com",
		"admin_email": "admin@example.com",
	}
}

func validSecrets(t *testing.T) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"service_account_key": makeServiceAccountKeyJSON(t),
	}
}

func TestValidate_HappyPath(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets(t)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	c := New()
	cases := []struct {
		name   string
		cfg    map[string]interface{}
		sec    map[string]interface{}
		wantOK bool
	}{
		{"missing domain", map[string]interface{}{"admin_email": "a@b.com"}, validSecrets(t), false},
		{"bad domain", map[string]interface{}{"domain": "noTLD", "admin_email": "a@b.com"}, validSecrets(t), false},
		{"missing admin", map[string]interface{}{"domain": "example.com"}, validSecrets(t), false},
		{"bad admin", map[string]interface{}{"domain": "example.com", "admin_email": "no-at-sign"}, validSecrets(t), false},
		{"missing key", validConfig(), map[string]interface{}{}, false},
		{"bad key json", validConfig(), map[string]interface{}{"service_account_key": "not-json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Validate(context.Background(), tc.cfg, tc.sec)
			if (err == nil) != tc.wantOK {
				t.Fatalf("Validate(%s) err = %v, wantOK=%v", tc.name, err, tc.wantOK)
			}
		})
	}
}

func TestValidate_DoesNotMakeNetworkCalls(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })

	c := New()
	if err := c.Validate(context.Background(), validConfig(), validSecrets(t)); err != nil {
		t.Fatalf("Validate hit the network or failed: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q): %v", ProviderName, err)
	}
	if _, ok := got.(*GoogleWorkspaceAccessConnector); !ok {
		t.Fatalf("registered type = %T, want *GoogleWorkspaceAccessConnector", got)
	}
}

func TestProvisionAccess_AddsGroupMember(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"created", http.StatusOK},
		{"conflict_idempotent", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenPath string
			var seenBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenPath = r.URL.Path
				seenBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(server.Close)

			c := New()
			c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
				return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
			}
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
				UserExternalID:     "alice@example.com",
				ResourceExternalID: "engineering@example.com",
				Role:               "MEMBER",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if !strings.Contains(seenPath, "/groups/engineering@example.com/members") {
				t.Fatalf("path = %q, want .../groups/engineering@example.com/members", seenPath)
			}
			var body directoryMemberAdd
			if err := json.Unmarshal(seenBody, &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Email != "alice@example.com" || body.Role != "MEMBER" {
				t.Fatalf("body = %+v", body)
			}
		})
	}
}

func TestProvisionAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}

// TestProvisionAccess_5xxIsTransient locks that a 5xx from the Admin SDK is
// classified as transient (via access.IsTransientStatus) so the worker retries
// it with backoff, rather than failing permanently like a 4xx. The Admin SDK
// aggressively rate-limits directory mutations, so this matters in production.
func TestProvisionAccess_5xxIsTransient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
	})
	if err == nil || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("expected transient error, got %v", err)
	}
}

// TestRevokeAccess_5xxIsTransient is the revoke-path counterpart of
// TestProvisionAccess_5xxIsTransient.
func TestRevokeAccess_5xxIsTransient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
	})
	if err == nil || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("expected transient error, got %v", err)
	}
}

// TestVerifyPermissions_ProbesProvider verifies the contract that
// VerifyPermissions probes the provider: a reachable, authorized provider
// yields no missing capabilities, while a probe failure (e.g. 403) marks the
// known capability unauthorized rather than silently reporting success.
func TestVerifyPermissions_ProbesProvider(t *testing.T) {
	t.Run("authorized probe -> no missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"users":[]}`))
		}))
		t.Cleanup(server.Close)

		c := New()
		c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
			return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
		}
		missing, err := c.VerifyPermissions(context.Background(), validConfig(), validSecrets(t), []string{"sync_identity"})
		if err != nil {
			t.Fatalf("VerifyPermissions: %v", err)
		}
		if len(missing) != 0 {
			t.Fatalf("missing = %v, want empty", missing)
		}
	})

	t.Run("forbidden probe -> capability unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		t.Cleanup(server.Close)

		c := New()
		c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
			return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
		}
		missing, err := c.VerifyPermissions(context.Background(), validConfig(), validSecrets(t), []string{"sync_identity"})
		if err != nil {
			t.Fatalf("VerifyPermissions: %v", err)
		}
		if len(missing) != 1 || !strings.HasPrefix(missing[0], "sync_identity") {
			t.Fatalf("missing = %v, want [sync_identity (...)]", missing)
		}
	})

	t.Run("unknown capability always missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"users":[]}`))
		}))
		t.Cleanup(server.Close)

		c := New()
		c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
			return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
		}
		missing, err := c.VerifyPermissions(context.Background(), validConfig(), validSecrets(t), []string{"provision_access"})
		if err != nil {
			t.Fatalf("VerifyPermissions: %v", err)
		}
		if len(missing) != 1 || !strings.Contains(missing[0], "no scope mapping") {
			t.Fatalf("missing = %v, want [provision_access (no scope mapping)]", missing)
		}
	})
}

// TestLicenseProvisionRevoke exercises the license:<product>/<sku> grant
// routing, which targets the Licensing API host (licensingBaseURL) rather
// than the Directory host. fakeDirectoryClient rewrites by path, so a single
// server serves both; this locks the previously-untested license code path.
func TestLicenseProvisionRevoke(t *testing.T) {
	var provisionPath, provisionBody, revokePath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			provisionPath = r.URL.Path
			provisionBody = string(b)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case http.MethodDelete:
			revokePath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	grant := access.AccessGrant{
		UserExternalID:     "alice@example.com",
		ResourceExternalID: "ignored-for-license",
		Role:               "license:Google-Apps/1010020020",
	}
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(t), grant); err != nil {
		t.Fatalf("ProvisionAccess(license): %v", err)
	}
	if !strings.Contains(provisionPath, "/apps/licensing/v1/product/Google-Apps/sku/1010020020/user") {
		t.Fatalf("provision path = %q, want licensing assign endpoint", provisionPath)
	}
	if !strings.Contains(provisionBody, `"userId":"alice@example.com"`) {
		t.Fatalf("provision body = %q, want userId", provisionBody)
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(t), grant); err != nil {
		t.Fatalf("RevokeAccess(license): %v", err)
	}
	if !strings.Contains(revokePath, "/apps/licensing/v1/product/Google-Apps/sku/1010020020/user/alice@example.com") {
		t.Fatalf("revoke path = %q, want licensing unassign endpoint", revokePath)
	}
}

func TestRevokeAccess_RemovesGroupMember(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"deleted", http.StatusNoContent},
		{"not_found_idempotent", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenMethod, seenPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenMethod, seenPath = r.Method, r.URL.Path
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)

			c := New()
			c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
				return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
			}
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
				UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
			})
			if err != nil {
				t.Fatalf("RevokeAccess: %v", err)
			}
			if seenMethod != http.MethodDelete {
				t.Fatalf("method = %q, want DELETE", seenMethod)
			}
			if !strings.HasSuffix(seenPath, "/groups/engineering@example.com/members/alice@example.com") {
				t.Fatalf("path = %q", seenPath)
			}
		})
	}
}

func TestRevokeAccess_4xxFailsPermanently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
	})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected 400 error, got %v", err)
	}
}

func TestListEntitlements_PagesUserGroups(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Query().Get("userKey") != "alice@example.com" {
			t.Fatalf("userKey = %q", r.URL.Query().Get("userKey"))
		}
		if r.URL.Query().Get("pageToken") == "" {
			page := directoryGroupsPage{
				Groups:        []directoryGroup{{ID: "g-1", Email: "engineering@example.com", Name: "Engineering"}},
				NextPageToken: "p2",
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		page := directoryGroupsPage{
			Groups: []directoryGroup{{ID: "g-2", Email: "ops@example.com", Name: "Ops"}},
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(t), "alice@example.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if hits != 2 {
		t.Fatalf("expected 2 page requests, got %d", hits)
	}
	if len(got) != 2 || got[0].ResourceExternalID != "g-1" || got[1].ResourceExternalID != "g-2" {
		t.Fatalf("got %+v", got)
	}
	for _, e := range got {
		if e.Source != "direct" || e.Role != "member" {
			t.Fatalf("entitlement %+v missing role/source", e)
		}
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(t), "alice@example.com"); err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestParseLicenseRole(t *testing.T) {
	pid, sku, ok := parseLicenseRole("license:Google-Apps/1010020020")
	if !ok || pid != "Google-Apps" || sku != "1010020020" {
		t.Fatalf("parseLicenseRole = %q/%q/%v", pid, sku, ok)
	}
	if _, _, ok := parseLicenseRole("group:engineering"); ok {
		t.Fatal("group: should not be parsed as license")
	}
	if _, _, ok := parseLicenseRole("license:bad"); ok {
		t.Fatal("license:bad should be rejected")
	}
}

func TestGetSSOMetadata(t *testing.T) {
	c := New()
	md, err := c.GetSSOMetadata(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md.Protocol != "oidc" {
		t.Fatalf("Protocol = %q", md.Protocol)
	}
	if !strings.HasSuffix(md.MetadataURL, "/.well-known/openid-configuration") {
		t.Fatalf("MetadataURL = %q", md.MetadataURL)
	}
}

func TestGetCredentialsMetadata_ReturnsKeyID(t *testing.T) {
	c := New()
	got, err := c.GetCredentialsMetadata(context.Background(), nil, validSecrets(t))
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if got["private_key_id"] != "kid-1" {
		t.Fatalf("private_key_id = %v, want kid-1", got["private_key_id"])
	}
	if got["client_email"] != "svc@proj-test.iam.gserviceaccount.com" {
		t.Fatalf("client_email = %v", got["client_email"])
	}
}

// fakeDirectoryClient routes Admin SDK calls to a local httptest server.
type fakeDirectoryClient struct {
	base string
	c    *http.Client
}

func (f *fakeDirectoryClient) Do(req *http.Request) (*http.Response, error) {
	rewritten := f.base + req.URL.Path
	if req.URL.RawQuery != "" {
		rewritten += "?" + req.URL.RawQuery
	}
	out, err := http.NewRequestWithContext(req.Context(), req.Method, rewritten, req.Body)
	if err != nil {
		return nil, err
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}
	return f.c.Do(out)
}

func TestSyncIdentities_PaginatesAndMaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pageToken") == "" {
			page := directoryUsersPage{
				Users: []directoryUser{
					{ID: "1", PrimaryEmail: "alice@example.com", Suspended: false, Name: struct {
						FullName string `json:"fullName"`
					}{FullName: "Alice"}},
				},
				NextPageToken: "p2",
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		page := directoryUsersPage{
			Users: []directoryUser{
				{ID: "2", PrimaryEmail: "bob@example.com", Suspended: true, Name: struct {
					FullName string `json:"fullName"`
				}{FullName: "Bob"}},
			},
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)

	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}

	var collected []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(t), "", func(batch []*access.Identity, _ string) error {
		collected = append(collected, batch...)
		return nil
	}); err != nil {
		t.Fatalf("SyncIdentities: %v", err)
	}
	if len(collected) != 2 {
		t.Fatalf("collected %d, want 2", len(collected))
	}
	if collected[0].DisplayName != "Alice" || collected[0].Status != "active" {
		t.Fatalf("first identity = %+v", collected[0])
	}
	if collected[1].Status != "suspended" {
		t.Fatalf("second status = %q, want suspended", collected[1].Status)
	}
}

// TestAdminSDKWriteScopes pins the scopes the connector mints for write
// paths. ProvisionAccess and RevokeAccess POST/DELETE against
// /groups/{id}/members and the Licensing API; both require non-readonly
// scopes. A regression here would cause production writes to 403 against
// real Google APIs while local tests (which bypass OAuth2 via httpClientFor)
// continue to pass.
func TestAdminSDKWriteScopes(t *testing.T) {
	want := map[string]bool{
		"https://www.googleapis.com/auth/admin.directory.group.member": true,
		"https://www.googleapis.com/auth/apps.licensing":               true,
	}
	got := make(map[string]bool, len(adminSDKWriteScopes))
	for _, s := range adminSDKWriteScopes {
		got[s] = true
		if strings.HasSuffix(s, ".readonly") && (strings.Contains(s, "group.member") || strings.Contains(s, "apps.licensing")) {
			t.Errorf("write scopes must not include readonly variant of %q", s)
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("adminSDKWriteScopes missing required scope %q", k)
		}
	}
	// Read scopes must remain readonly-only.
	for _, s := range adminSDKScopes {
		if !strings.HasSuffix(s, ".readonly") {
			t.Errorf("adminSDKScopes must be read-only; got %q", s)
		}
	}
}

// TestProvisionAccess_UsesWriteClient asserts ProvisionAccess routes through
// directoryWriteClient (i.e. the writeHTTPClientFor hook) and not the
// read-only directoryClient. Read-only paths (Connect, SyncIdentities,
// ListEntitlements) must not be observed by the write hook.
func TestProvisionAccess_UsesWriteClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	var readCalls, writeCalls int
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		readCalls++
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	c.writeHTTPClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		writeCalls++
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}

	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if readCalls != 0 {
		t.Errorf("read client builder invoked %d times; ProvisionAccess must use the write client only", readCalls)
	}
	if writeCalls != 1 {
		t.Errorf("write client builder invoked %d times; want 1", writeCalls)
	}
}

// TestRevokeAccess_UsesWriteClient mirrors TestProvisionAccess_UsesWriteClient.
func TestRevokeAccess_UsesWriteClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	var readCalls, writeCalls int
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		readCalls++
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	c.writeHTTPClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		writeCalls++
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}

	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(t), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "engineering@example.com", Role: "MEMBER",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if readCalls != 0 {
		t.Errorf("read client builder invoked %d times; RevokeAccess must use the write client only", readCalls)
	}
	if writeCalls != 1 {
		t.Errorf("write client builder invoked %d times; want 1", writeCalls)
	}
}

// TestListEntitlements_UsesReadClient asserts that ListEntitlements stays on
// the read-only directoryClient (least privilege).
func TestListEntitlements_UsesReadClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"groups":[]}`))
	}))
	t.Cleanup(server.Close)

	var readCalls, writeCalls int
	c := New()
	c.httpClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		readCalls++
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}
	c.writeHTTPClientFor = func(_ context.Context, _ Config, _ Secrets) (httpDoer, error) {
		writeCalls++
		return &fakeDirectoryClient{base: server.URL, c: server.Client()}, nil
	}

	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(t), "alice@example.com"); err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if writeCalls != 0 {
		t.Errorf("write client builder invoked %d times; ListEntitlements must use the read-only client", writeCalls)
	}
	if readCalls != 1 {
		t.Errorf("read client builder invoked %d times; want 1", readCalls)
	}
}
