package slack

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

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"bot_token": "xoxb-1234567890-abcdef"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsNonXoxbToken(t *testing.T) {
	if err := New().Validate(context.Background(), nil, map[string]interface{}{"bot_token": "abc"}); err == nil {
		t.Error("non-xoxb token: want error")
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
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
		if !strings.HasSuffix(r.URL.Path, "/auth.test") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"team":"uney","user":"bot","team_id":"T1","user_id":"U1"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestConnect_FailureViaApiError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.Connect(context.Background(), nil, validSecrets())
	if err == nil || !strings.Contains(err.Error(), "invalid_auth") {
		t.Errorf("Connect err = %v; want invalid_auth", err)
	}
}

func TestSync_PaginatesUsersList(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{"ok":true,"members":[{"id":"U1","name":"alice","real_name":"Alice","profile":{"email":"alice@uney.com","display_name":"Alice"}}],"response_metadata":{"next_cursor":"NEXT"}}`))
			return
		}
		if r.URL.Query().Get("cursor") != "NEXT" {
			t.Errorf("cursor = %q", r.URL.Query().Get("cursor"))
		}
		_, _ = w.Write([]byte(`{"ok":true,"members":[{"id":"U2","name":"bot","is_bot":true,"profile":{}}],"response_metadata":{"next_cursor":""}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), nil, validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2", len(got))
	}
	if got[1].Type != access.IdentityTypeServiceAccount {
		t.Errorf("bot type = %q; want service_account", got[1].Type)
	}
}

func TestSync_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"missing_scope"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.SyncIdentities(context.Background(), nil, validSecrets(), "", func([]*access.Identity, string) error { return nil }); err == nil {
		t.Error("Sync: want error")
	}
}

func TestGetSSOMetadata_NonEnterpriseReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"team":{"id":"T1","name":"uney","domain":"uney"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	md, err := c.GetSSOMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md != nil {
		t.Errorf("md = %+v; want nil", md)
	}
}

func TestGetSSOMetadata_EnterpriseGridReturnsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"team":{"id":"T1","domain":"uney","enterprise_id":"E1","enterprise_name":"Uney"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	md, err := c.GetSSOMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if md == nil || md.Protocol != "saml" {
		t.Fatalf("md = %+v", md)
	}
}

// ---------- advanced capability tests ----------

func TestProvisionAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/conversations.invite") {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"channel":{"id":"C123"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{
		UserExternalID: "U1", ResourceExternalID: "C123",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
}

func TestProvisionAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"already_in_channel"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{
		UserExternalID: "U1", ResourceExternalID: "C123",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess (idempotent): %v", err)
	}
}

func TestProvisionAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), nil, validSecrets(), access.AccessGrant{
		UserExternalID: "U1", ResourceExternalID: "C999",
	})
	if err == nil || !strings.Contains(err.Error(), "channel_not_found") {
		t.Fatalf("ProvisionAccess: want channel_not_found error, got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/conversations.kick") {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{
		UserExternalID: "U1", ResourceExternalID: "C123",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

func TestRevokeAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"not_in_channel"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{
		UserExternalID: "U1", ResourceExternalID: "C123",
	})
	if err != nil {
		t.Fatalf("RevokeAccess (idempotent): %v", err)
	}
}

func TestRevokeAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"missing_scope"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), nil, validSecrets(), access.AccessGrant{
		UserExternalID: "U1", ResourceExternalID: "C123",
	})
	if err == nil || !strings.Contains(err.Error(), "missing_scope") {
		t.Fatalf("RevokeAccess: want missing_scope error, got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/users.conversations") {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"channels":[{"id":"C1","name":"general"},{"id":"C2","name":"random"}],"response_metadata":{"next_cursor":""}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "U1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entitlements, want 2", len(got))
	}
	if got[0].ResourceExternalID != "C1" || got[0].Role != "member" || got[0].Source != "direct" {
		t.Fatalf("entitlement[0] = %+v", got[0])
	}
}

func TestListEntitlements_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"channels":[],"response_metadata":{"next_cursor":""}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), nil, validSecrets(), "U1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d entitlements, want 0", len(got))
	}
}
