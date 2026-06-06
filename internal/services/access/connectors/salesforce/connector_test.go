package salesforce

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

func validConfig() map[string]interface{} {
	return map[string]interface{}{"instance_url": "https://acme.my.salesforce.com"}
}
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"access_token": "00DSF12345aaaa"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing instance_url")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"instance_url": "acme.my.salesforce.com"}, validSecrets()); err == nil {
		t.Error("missing scheme")
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
			_, _ = w.Write([]byte(`{"totalSize":2,"done":false,"nextRecordsUrl":"/services/data/v59.0/query/0r80000000000ABC-2000","records":[{"Id":"u1","Name":"Alice","Email":"a@b.com","IsActive":true}]}`))
			return
		}
		if !strings.Contains(r.URL.Path, "0r80000000000ABC-2000") {
			t.Errorf("unexpected nextRecordsUrl path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"totalSize":2,"done":true,"records":[{"Id":"u2","Name":"Bob","Email":"b@b.com","IsActive":false}]}`))
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
	if got[1].Status != "inactive" {
		t.Errorf("expected u2 inactive, got %q", got[1].Status)
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
	if short == "" || strings.Contains(short, "SF12345") {
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
	if !strings.HasSuffix(md.MetadataURL, "/identity/saml/metadata") {
		t.Errorf("metadata URL = %q", md.MetadataURL)
	}
}

// ---------- advanced capability tests ----------

func TestProvisionAccess_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"psa-1"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
}

func TestProvisionAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`[{"errorCode":"DUPLICATE_VALUE"}]`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err != nil {
		t.Fatalf("ProvisionAccess idempotent: %v", err)
	}
}

func TestProvisionAccess_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`[{"message":"forbidden"}]`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403, got %v", err)
	}
}

// TestProvisionAccess_Transient verifies a 5xx is classified as a
// transient failure (so the worker retries with backoff) via the shared
// access.IsTransientStatus helper, matching every other connector.
func TestProvisionAccess_Transient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"message":"upstream busy"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err == nil || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("want transient error, got %v", err)
	}
}

func TestRevokeAccess_Transient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"records":[{"Id":"psa-1"}]}`))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"message":"bad gateway"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err == nil || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("want transient error, got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"records":[{"Id":"psa-1"}]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

func TestRevokeAccess_Idempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err != nil {
		t.Fatalf("RevokeAccess idempotent: %v", err)
	}
}

func TestRevokeAccess_Failure(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"records":[{"Id":"psa-1"}]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403, got %v", err)
	}
}

func TestListEntitlements_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"records":[{"PermissionSet":{"Name":"Admin"},"PermissionSetId":"ps-1"},{"PermissionSet":{"Name":"User"},"PermissionSetId":"ps-2"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Role != "Admin" {
		t.Fatalf("got %+v", got[0])
	}
}

func TestListEntitlements_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "u-1")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d entitlements, want 0", len(got))
	}
}

// TestEscapeSOQLLiteral covers the pure-local escape helper that guards the
// SOQL string-literal interpolation in RevokeAccess / ListEntitlements.
func TestEscapeSOQLLiteral(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`uid-1`, `uid-1`},
		{`x' OR '1'='1`, `x\' OR \'1\'=\'1`},
		{`back\slash`, `back\\slash`},
		{`mixed'\both`, `mixed\'\\both`},
	}
	for _, tc := range cases {
		if got := escapeSOQLLiteral(tc.in); got != tc.want {
			t.Errorf("escapeSOQLLiteral(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestRevokeAccess_QuoteInExternalIDDoesNotInjectSOQL is a regression test
// for the SOQL injection vulnerability where url.QueryEscape alone left the
// literal vulnerable because Salesforce URL-decodes the `q=` parameter back
// to a raw `'` before parsing. The fix doubles the quote in the literal
// (escapeSOQLLiteral) so the query the server sees still has the attacker
// payload contained inside the AssigneeId string literal.
func TestRevokeAccess_QuoteInExternalIDDoesNotInjectSOQL(t *testing.T) {
	const payload = `x' OR '1'='1`
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			capturedQuery = r.URL.Query().Get("q")
			_, _ = w.Write([]byte(`{"records":[]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: payload, ResourceExternalID: "ps-1"})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	// After URL-decoding by net/http, the captured SOQL must still have
	// the attacker payload escaped (i.e. `\'`) so it stays inside the
	// AssigneeId string literal rather than terminating it and injecting
	// a tautology.
	if !strings.Contains(capturedQuery, `AssigneeId='x\' OR \'1\'=\'1'`) {
		t.Fatalf("expected escaped literal in SOQL; got: %s", capturedQuery)
	}
	if strings.Contains(capturedQuery, `AssigneeId='x' OR '1'='1'`) {
		t.Fatalf("SOQL still contains raw injection payload: %s", capturedQuery)
	}
}

// TestListEntitlements_QuoteInUserIDDoesNotInjectSOQL is the equivalent
// regression test for the ListEntitlements SOQL builder.
func TestListEntitlements_QuoteInUserIDDoesNotInjectSOQL(t *testing.T) {
	const payload = `u' OR Name LIKE '%`
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), payload); err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if !strings.Contains(capturedQuery, `AssigneeId='u\' OR Name LIKE \'%'`) {
		t.Fatalf("expected escaped literal in SOQL; got: %s", capturedQuery)
	}
}

// TestRevokeAccess_QueryErrorPropagates is a regression test for the bug
// where RevokeAccess silently returned nil when the SOQL lookup query
// failed (5xx, auth failure, network drop). The lookup error must surface
// to the caller so the worker can retry per docs/architecture.md §2 — a 5xx on
// the lookup is NOT the same as "no matching assignment", which is the
// legitimate idempotency case handled by len(Records) == 0.
func TestRevokeAccess_QueryErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the SOQL query is issued; respond 500 so the worker sees
		// a retriable error rather than a fake success.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal error"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err == nil {
		t.Fatal("RevokeAccess returned nil on a 500 SOQL query; want error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want it to surface the 500 status", err)
	}
	if !strings.Contains(err.Error(), "revoke query") {
		t.Errorf("err = %v; want the wrapped %q prefix", err, "revoke query")
	}
}

// TestRevokeAccess_QueryAuthErrorPropagates exercises a 401 on the SOQL
// lookup — same shape as the 5xx case above. Without this fix a stale
// access token would mark the revoke as successful when nothing was
// actually deleted.
func TestRevokeAccess_QueryAuthErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"INVALID_SESSION_ID"}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "uid-1", ResourceExternalID: "ps-1"})
	if err == nil {
		t.Fatal("RevokeAccess returned nil on a 401 SOQL query; want error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v; want it to surface the 401 status", err)
	}
}
