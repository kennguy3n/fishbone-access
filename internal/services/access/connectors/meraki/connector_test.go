package meraki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	return map[string]interface{}{"organization_id": "1234567"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"token": "mk_AAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
	}
}

// TestValidate_RequiresOrganizationID asserts that a missing organization_id is
// caught at Validate() time (fail-closed) rather than being deferred to the
// first sync/provision call. Every Meraki endpoint is org-scoped, so the field
// is part of the typed Config and enforced by Config.validate().
func TestValidate_RequiresOrganizationID(t *testing.T) {
	c := New()
	err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets())
	if err == nil || !strings.Contains(err.Error(), "organization_id") {
		t.Fatalf("err = %v; want organization_id required at validate time", err)
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

func TestSync_DefaultsStatusActiveRegardlessOfHasApiKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// getOrganizationAdmins returns a bare JSON array, not a {"data":[...]} envelope.
		body := []map[string]interface{}{
			{"id": "a1", "email": "a@x.com", "name": "A", "hasApiKey": false},
			{"id": "a2", "email": "b@x.com", "name": "B", "hasApiKey": true},
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
	if len(got) != 2 {
		t.Fatalf("want 2 identities; got %d", len(got))
	}
	for _, id := range got {
		if id.Status != "active" {
			t.Errorf("%s status = %q; want active (Meraki API has no per-admin enable flag)", id.ExternalID, id.Status)
		}
	}
}

// TestSync_OrgScopedSingleRequest is a regression test for the fix that points
// identity sync at the org-scoped getOrganizationAdmins endpoint
// (/api/v1/organizations/{organizationId}/admins). That endpoint returns a bare
// JSON array and is not paginated, so Sync must issue exactly one request and
// decode the array directly (the previous code hit a non-existent /api/v1/admins
// and expected a paginated {"data":[...]} envelope).
func TestSync_OrgScopedSingleRequest(t *testing.T) {
	const wantPath = "/api/v1/organizations/1234567/admins"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Cisco-Meraki-API-Key") == "" {
			t.Errorf("expected X-Cisco-Meraki-API-Key header")
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %q; want %q", r.URL.Path, wantPath)
		}
		var arr []map[string]interface{}
		for i := 0; i < 150; i++ {
			arr = append(arr, map[string]interface{}{"id": fmt.Sprintf("u%d", i), "email": fmt.Sprintf("u%d@x.com", i), "name": fmt.Sprintf("U%d", i)})
		}
		b, _ := json.Marshal(arr)
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
	if len(got) != 150 || calls != 1 {
		t.Fatalf("got=%d calls=%d; want 150 identities in 1 request", len(got), calls)
	}
}

// TestSync_RequiresOrganizationID asserts that identity sync fails fast when the
// org id is absent, mirroring the org-scoped audit + admin endpoints.
func TestSync_RequiresOrganizationID(t *testing.T) {
	c := New()
	c.httpClient = func() httpDoer { return &http.Client{} }
	err := c.SyncIdentities(context.Background(), map[string]interface{}{}, validSecrets(), "", func([]*access.Identity, string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "organization_id") {
		t.Fatalf("err = %v; want organization_id required", err)
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
	got, _ := md["token_short"].(string)
	if !strings.Contains(got, "...") || strings.Contains(got, "AAAA1234") {
		t.Errorf("redaction failed: %q", got)
	}
}
