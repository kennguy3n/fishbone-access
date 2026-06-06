package gitlab

import (
	"context"
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

func validConfig() map[string]interface{} { return map[string]interface{}{"group_id": "12345"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "glpat-aaaaBBBB1234ZZZZ"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing group")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"group_id": "1", "base_url": "gitlab.example.com"}, validSecrets()); err == nil {
		t.Error("base_url without scheme")
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
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Header().Set("X-Next-Page", "2")
			_, _ = w.Write([]byte(`[{"id":1,"username":"alice","name":"Alice","state":"active"}]`))
			return
		}
		if r.URL.Query().Get("page") != "2" {
			t.Errorf("page = %q", r.URL.Query().Get("page"))
		}
		// X-Next-Page absent => last page.
		_, _ = w.Write([]byte(`[{"id":2,"username":"bob","name":"Bob","state":"blocked"}]`))
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
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if page < 2 {
		t.Fatalf("expected pagination, calls = %d", page)
	}
	if got[1].Status != "blocked" {
		t.Errorf("expected u2 blocked, got %q", got[1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// TestListEntitlements_MalformedBody pins that a 200 response with an
// undecodable body surfaces an error instead of being swallowed as
// "no entitlements" (which would silently report a user as having no access
// on a transient/garbled response). A 404 is still the documented soft-skip.
func TestListEntitlements_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not json"))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err == nil {
		t.Fatalf("expected decode error, got nil (entitlements=%v)", got)
	}
	if !strings.Contains(err.Error(), "decode entitlements") {
		t.Errorf("err = %v; want decode entitlements error", err)
	}
}

func TestListEntitlements_NotMemberSoftSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("404 should soft-skip to empty, got err %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entitlements; want 0", len(got))
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "aaaaBBBB") {
		t.Errorf("token_short = %q", short)
	}
}

func TestGetSSOMetadata(t *testing.T) {
	md, err := New().GetSSOMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if md == nil || md.Protocol != "saml" {
		t.Fatalf("expected SAML, got %+v", md)
	}
	if !strings.Contains(md.MetadataURL, "/groups/12345/-/saml/metadata") {
		t.Errorf("metadata URL = %q", md.MetadataURL)
	}
}
