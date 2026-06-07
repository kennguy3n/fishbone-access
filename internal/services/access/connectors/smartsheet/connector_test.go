package smartsheet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "ssAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("expected Bearer auth")
		}
		page := r.URL.Query().Get("page")
		if calls == 1 && page != "1" {
			t.Errorf("page = %q", page)
		}
		if calls == 2 && page != "2" {
			t.Errorf("page = %q", page)
		}
		users := []map[string]interface{}{
			{"id": calls*10 + 1, "email": fmt.Sprintf("a%d@x.com", calls), "name": "Alice", "status": "ACTIVE"},
			{"id": calls*10 + 2, "email": fmt.Sprintf("b%d@x.com", calls), "name": "Bob", "status": "DECLINED"},
		}
		b, _ := json.Marshal(map[string]interface{}{
			"pageNumber": calls,
			"pageSize":   pageSize,
			"totalPages": 2,
			"totalCount": 4,
			"data":       users,
		})
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
	if len(got) != 4 {
		t.Fatalf("len = %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
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

func newAdvancedTestConnector(srv *httptest.Server) *SmartsheetAccessConnector {
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice@example.com", ResourceExternalID: "1234567890", Role: "EDITOR",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if !strings.HasSuffix(got.path, "/2.0/sheets/1234567890/shares") || got.method != http.MethodPost {
		t.Errorf("call = %s %s", got.method, got.path)
	}
}

func TestProvisionAccess_DuplicateIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errorCode":1020,"message":"User already shared"}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "a@b.com", ResourceExternalID: "1234567890",
	}); err != nil {
		t.Fatalf("1020 should be idempotent; got %v", err)
	}
}

func TestProvisionAccess_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "a@b.com", ResourceExternalID: "1234567890",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var deletedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"data":[{"id":"SHARE-1","type":"USER","email":"a@b.com","accessLevel":"EDITOR"}],"pageNumber":1,"totalPages":1}`))
		case http.MethodDelete:
			deletedPath = r.URL.Path
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "a@b.com", ResourceExternalID: "1234567890",
	}); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !strings.HasSuffix(deletedPath, "/2.0/sheets/1234567890/shares/SHARE-1") {
		t.Errorf("deleted path = %q", deletedPath)
	}
}

func TestRevokeAccess_NotSharedIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"data":[],"pageNumber":1,"totalPages":1}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "a@b.com", ResourceExternalID: "1234567890",
	}); err != nil {
		t.Fatalf("missing share should be idempotent; got %v", err)
	}
}

func TestListEntitlements_FiltersByUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/2.0/sheets"):
			_, _ = w.Write([]byte(`{"data":[{"id":"1","name":"S1"},{"id":"2","name":"S2"}],"pageNumber":1,"totalPages":1}`))
		case strings.HasSuffix(r.URL.Path, "/2.0/sheets/1/shares"):
			_, _ = w.Write([]byte(`{"data":[{"id":"sh1","type":"USER","email":"a@b.com","accessLevel":"EDITOR"}]}`))
		case strings.HasSuffix(r.URL.Path, "/2.0/sheets/2/shares"):
			_, _ = w.Write([]byte(`{"data":[{"id":"sh2","type":"USER","email":"x@y.com","accessLevel":"VIEWER"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "a@b.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "1" || got[0].Role != "EDITOR" {
		t.Fatalf("got = %+v", got)
	}
}

// ListEntitlements fans out one shares request per sheet and can hit
// Smartsheet's 300 req/min limit. A 429 with a Retry-After header must be
// absorbed via retry rather than failing the whole call.
func TestListEntitlements_RetriesOn429(t *testing.T) {
	var sheetsCalls, sharesCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/2.0/sheets"):
			// First sheets request is rate-limited, then succeeds.
			if atomic.AddInt32(&sheetsCalls, 1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"errorCode":4003,"message":"Rate limit exceeded"}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"1","name":"S1"}],"pageNumber":1,"totalPages":1}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/2.0/sheets/1/shares"):
			// First shares request is rate-limited, then succeeds.
			if atomic.AddInt32(&sharesCalls, 1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"errorCode":4003,"message":"Rate limit exceeded"}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"sh1","type":"USER","email":"a@b.com","accessLevel":"EDITOR"}],"pageNumber":1,"totalPages":1}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := newAdvancedTestConnector(srv)
	ents, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "a@b.com")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(ents) != 1 || ents[0].ResourceExternalID != "1" || ents[0].Role != "EDITOR" {
		t.Fatalf("ents = %+v", ents)
	}
	if atomic.LoadInt32(&sheetsCalls) != 2 || atomic.LoadInt32(&sharesCalls) != 2 {
		t.Fatalf("expected one retry each: sheets=%d shares=%d", sheetsCalls, sharesCalls)
	}
}

// After exhausting retries, a persistent 429 surfaces as an error rather
// than being silently treated as "no entitlements".
func TestListEntitlements_PersistentRateLimitSurfacesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/2.0/sheets") {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errorCode":4003}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := newAdvancedTestConnector(srv)
	_, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "a@b.com")
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected 429 error after retries, got %v", err)
	}
}

func TestProvisionRevoke_RejectMissing(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "x"}); err == nil {
		t.Error("provision should require email")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "a@b.com"}); err == nil {
		t.Error("revoke should require sheet id")
	}
}

// keep unused imports used in case the file shrinks
var _ = json.RawMessage(nil)
var _ = fmt.Sprintf
