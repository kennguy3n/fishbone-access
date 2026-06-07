package figma

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

func validConfig() map[string]interface{} { return map[string]interface{}{"team_id": "123"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "figd_aaaaBBBBccccDDDD"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing team")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing token")
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
			_, _ = w.Write([]byte(`{"members":[{"id":"u1","handle":"alice","email":"a@b.com"}],"cursor":{"after":"AFT"}}`))
			return
		}
		if r.URL.Query().Get("cursor") != "AFT" {
			t.Errorf("cursor = %q", r.URL.Query().Get("cursor"))
		}
		_, _ = w.Write([]byte(`{"members":[{"id":"u2","handle":"bob","email":"b@b.com"}],"cursor":{"after":""}}`))
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
}

func TestSync_EscapesOpaqueCursor(t *testing.T) {
	// Figma's pagination cursor is an opaque token that can contain
	// URL-reserved characters (e.g. '+', '/', '='). It must be sent as a
	// properly percent-encoded query value so the server receives it
	// verbatim after decoding.
	const rawCursor = "ey+ab/cd=="
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`{"members":[{"id":"u1","handle":"alice","email":"a@b.com"}],"cursor":{"after":"` + rawCursor + `"}}`))
			return
		}
		if got := r.URL.Query().Get("cursor"); got != rawCursor {
			t.Errorf("decoded cursor = %q; want %q (raw query: %q)", got, rawCursor, r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"members":[{"id":"u2","handle":"bob","email":"b@b.com"}],"cursor":{"after":""}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(_ []*access.Identity, _ string) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if page < 2 {
		t.Fatalf("expected pagination, calls = %d", page)
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

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "BBBBcccc") {
		t.Errorf("token_short = %q", short)
	}
}

// ---------- advanced capability tests ----------

func newAdvancedTestConnector(srv *httptest.Server) *FigmaAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	var captured struct{ path, body string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		captured.body = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"m1"}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u1", ResourceExternalID: "proj-1", Role: "editor",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if !strings.HasSuffix(captured.path, "/projects/proj-1/members") {
		t.Errorf("path = %q", captured.path)
	}
	if !strings.Contains(captured.body, `"editor"`) {
		t.Errorf("body missing role: %s", captured.body)
	}
}

func TestProvisionAccess_409Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u1", ResourceExternalID: "proj-1",
	}); err != nil {
		t.Fatalf("409 should be idempotent; got %v", err)
	}
}

func TestProvisionAccess_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u1", ResourceExternalID: "proj-1",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var captured struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u1", ResourceExternalID: "proj-1",
	}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if captured.method != http.MethodDelete {
		t.Errorf("method = %q", captured.method)
	}
	if !strings.HasSuffix(captured.path, "/projects/proj-1/members/u1") {
		t.Errorf("path = %q", captured.path)
	}
}

func TestRevokeAccess_404Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "u1", ResourceExternalID: "proj-1",
	}); err != nil {
		t.Fatalf("404 should be idempotent; got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/teams/123/projects"):
			_, _ = w.Write([]byte(`{"projects":[{"id":"p1","name":"P1"},{"id":"p2","name":"P2"}]}`))
		case strings.HasSuffix(r.URL.Path, "/projects/p1/members"):
			_, _ = w.Write([]byte(`{"members":[{"id":"u1","role":"editor"}]}`))
		case strings.HasSuffix(r.URL.Path, "/projects/p2/members"):
			_, _ = w.Write([]byte(`{"members":[{"id":"u9"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "p1" || got[0].Role != "editor" {
		t.Fatalf("got = %+v", got)
	}
}

func TestProvisionRevoke_RejectMissing(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "x"}); err == nil {
		t.Error("provision should require user id")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "u"}); err == nil {
		t.Error("revoke should require resource id")
	}
}
