package helpscout

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "hsAAAA1234bbbbCCCC"}
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
		if calls == 1 {
			_, _ = w.Write([]byte(`{"_embedded":{"users":[{"id":1,"firstName":"Alice","lastName":"Adams","email":"a@b.com","type":"user"}]},"page":{"size":50,"totalElements":2,"totalPages":2,"number":1}}`))
			return
		}
		if r.URL.Query().Get("page") != "2" {
			t.Errorf("page = %q", r.URL.Query().Get("page"))
		}
		_, _ = w.Write([]byte(`{"_embedded":{"users":[{"id":2,"firstName":"Bob","lastName":"Brown","email":"b@b.com","type":"team"}]},"page":{"size":50,"totalElements":2,"totalPages":2,"number":2}}`))
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
	if calls < 2 {
		t.Fatalf("expected pagination, calls = %d", calls)
	}
	if got[1].Type != access.IdentityTypeServiceAccount {
		t.Errorf("expected service account for type=team, got %v", got[1].Type)
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

// ---------- advanced capability tests ----------

func newAdvancedTestConnector(srv *httptest.Server) *HelpScoutAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	var got struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "10", ResourceExternalID: "20",
	}); err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if got.method != http.MethodPut || !strings.HasSuffix(got.path, "/teams/20/members/10") {
		t.Errorf("call = %s %s", got.method, got.path)
	}
}

func TestProvisionAccess_409Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "10", ResourceExternalID: "20",
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
		UserExternalID: "10", ResourceExternalID: "20",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var got struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "10", ResourceExternalID: "20",
	}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if got.method != http.MethodDelete || !strings.HasSuffix(got.path, "/teams/20/members/10") {
		t.Errorf("call = %s %s", got.method, got.path)
	}
}

func TestRevokeAccess_404Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "10", ResourceExternalID: "20",
	}); err != nil {
		t.Fatalf("404 should be idempotent; got %v", err)
	}
}

func TestListEntitlements_FiltersByUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/teams/1/members"):
			_, _ = w.Write([]byte(`{"_embedded":{"users":[{"id":10},{"id":11}]},"page":{"size":50,"totalElements":2,"totalPages":1,"number":1}}`))
		case strings.HasSuffix(r.URL.Path, "/teams/2/members"):
			_, _ = w.Write([]byte(`{"_embedded":{"users":[{"id":12}]},"page":{"size":50,"totalElements":1,"totalPages":1,"number":1}}`))
		case strings.HasSuffix(r.URL.Path, "/teams"):
			_, _ = w.Write([]byte(`{"_embedded":{"teams":[{"id":1,"name":"A"},{"id":2,"name":"B"}]},"page":{"size":50,"totalElements":2,"totalPages":1,"number":1}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "10")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "1" {
		t.Fatalf("got = %+v", got)
	}
}

// Regression: membership resolution must use the documented members LISTING
// endpoint (GET /teams/{id}/members), never a direct GET on an individual
// member resource — the live Help Scout API exposes membership only via the
// listing. Each team is listed exactly once, and the scan returns as soon as
// the user is found.
func TestListEntitlements_UsesMemberListing(t *testing.T) {
	const teams = 5
	teamList := make([]string, 0, teams)
	for i := 1; i <= teams; i++ {
		teamList = append(teamList, fmt.Sprintf(`{"id":%d,"name":"T%d"}`, i, i))
	}
	var mu sync.Mutex
	listCalls := map[string]int{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.Contains(path, "/members/"):
			t.Errorf("individual member resource probed; must use the listing endpoint: %s", path)
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(path, "/members"):
			mu.Lock()
			listCalls[path]++
			mu.Unlock()
			// User 7 belongs only to team 3.
			if strings.HasSuffix(path, "/teams/3/members") {
				_, _ = w.Write([]byte(`{"_embedded":{"users":[{"id":99},{"id":7}]},"page":{"size":50,"totalElements":2,"totalPages":1,"number":1}}`))
			} else {
				_, _ = w.Write([]byte(`{"_embedded":{"users":[{"id":99}]},"page":{"size":50,"totalElements":1,"totalPages":1,"number":1}}`))
			}
		case strings.HasSuffix(path, "/teams"):
			fmt.Fprintf(w, `{"_embedded":{"teams":[%s]},"page":{"size":50,"totalElements":%d,"totalPages":1,"number":1}}`,
				strings.Join(teamList, ","), teams)
		default:
			t.Errorf("unexpected request %s %s", r.Method, path)
		}
	}))
	t.Cleanup(srv.Close)

	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "7")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "3" {
		t.Fatalf("got = %+v; want single entitlement for team 3", got)
	}
	if len(listCalls) != teams {
		t.Fatalf("listed %d distinct member endpoints; want %d (one per team)", len(listCalls), teams)
	}
	for path, n := range listCalls {
		if n != 1 {
			t.Fatalf("endpoint %s listed %d times; want exactly 1", path, n)
		}
	}
}

// Regression: a transport failure while scanning a team's members must
// propagate, never silently yielding zero entitlements — under-reporting a
// user's access in an access-control system is a security concern.
func TestListEntitlements_MemberListErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/teams/1/members"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
		case strings.HasSuffix(r.URL.Path, "/teams"):
			_, _ = w.Write([]byte(`{"_embedded":{"teams":[{"id":1,"name":"A"}]},"page":{"size":50,"totalElements":1,"totalPages":1,"number":1}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "10"); err == nil {
		t.Fatal("expected error from 500 on members listing, got nil")
	} else if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("err = %v; want a status 500 error", err)
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
