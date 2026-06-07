package monday

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

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "abcdEFGH1234WXYZ"}
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
		// build a response of pageSize users on page 1, 1 user on page 2.
		if calls == 1 {
			users := make([]map[string]interface{}, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				users = append(users, map[string]interface{}{
					"id":    i + 1,
					"name":  fmt.Sprintf("User %d", i+1),
					"email": fmt.Sprintf("u%d@example.com", i+1),
				})
			}
			body, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{"users": users}})
			_, _ = w.Write(body)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":9999,"name":"Last","email":"last@example.com"}]}}`))
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
	if len(got) != pageSize+1 {
		t.Fatalf("len = %d", len(got))
	}
	if calls < 2 {
		t.Fatalf("expected pagination, calls = %d", calls)
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

// TestSync_DisabledUserMapsToDisabled is a regression test ensuring a Monday
// user with enabled:false maps to Status "disabled" (not "deleted"). Monday's
// enabled:false is a deactivated-but-present account; "deleted" diverged from
// the taxonomy peers use (microsoft/mezmo map accountEnabled=false→"disabled")
// and could mislead downstream reconciliation distinguishing removed vs
// deactivated users.
func TestSync_DisabledUserMapsToDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[
			{"id":1,"name":"Active User","email":"a@example.com","enabled":true},
			{"id":2,"name":"Off User","email":"b@example.com","enabled":false}
		]}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	if err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Status != "active" {
		t.Errorf("enabled user status = %q; want active", got[0].Status)
	}
	if got[1].Status != "disabled" {
		t.Errorf("disabled user status = %q; want disabled", got[1].Status)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	short, _ := md["token_short"].(string)
	if short == "" || strings.Contains(short, "EFGH1234") {
		t.Errorf("token_short = %q; expected redacted form", short)
	}
	if !strings.HasPrefix(short, "abcd") {
		t.Errorf("token_short prefix = %q", short)
	}
}

// ---------- advanced capability tests ----------

func newAdvancedTestConnector(srv *httptest.Server) *MondayAccessConnector {
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	return c
}

func TestProvisionAccess_HappyPath(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1024)
		n, _ := r.Body.Read(b)
		captured = string(b[:n])
		_, _ = w.Write([]byte(`{"data":{"add_users_to_board":[42]}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "7", ResourceExternalID: "42", Role: "subscriber",
	})
	if err != nil {
		t.Fatalf("ProvisionAccess: %v", err)
	}
	if !strings.Contains(captured, "add_users_to_board") {
		t.Errorf("query missing mutation: %s", captured)
	}
	if !strings.Contains(captured, "board_id: 42") {
		t.Errorf("query missing board id: %s", captured)
	}
	if !strings.Contains(captured, "user_ids: [7]") {
		t.Errorf("query missing user id: %s", captured)
	}
}

func TestProvisionAccess_AlreadySubscribedIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"User is already a subscriber"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "7", ResourceExternalID: "42",
	})
	if err != nil {
		t.Fatalf("already-subscriber should be idempotent; got %v", err)
	}
}

func TestProvisionAccess_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"Permission denied"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "7", ResourceExternalID: "42",
	})
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("expected permission denied; got %v", err)
	}
}

func TestRevokeAccess_HappyPath(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1024)
		n, _ := r.Body.Read(b)
		captured = string(b[:n])
		_, _ = w.Write([]byte(`{"data":{"delete_subscribers_from_board":[7]}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "7", ResourceExternalID: "42",
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
	if !strings.Contains(captured, "delete_subscribers_from_board") {
		t.Errorf("query missing mutation: %s", captured)
	}
}

func TestRevokeAccess_NotSubscribedIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"User is not subscribed to board"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "7", ResourceExternalID: "42",
	})
	if err != nil {
		t.Fatalf("not-subscribed should be idempotent; got %v", err)
	}
}

func TestListEntitlements_FiltersByUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"boards":[
			{"id":42,"name":"Marketing","subscribers":[{"id":7},{"id":9}]},
			{"id":99,"name":"Eng","subscribers":[{"id":1}]}
		]}}`))
	}))
	t.Cleanup(srv.Close)
	c := newAdvancedTestConnector(srv)
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "7")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 1 || got[0].ResourceExternalID != "42" {
		t.Fatalf("got = %+v", got)
	}
}

func TestListEntitlements_RejectsEmptyUser(t *testing.T) {
	if _, err := New().ListEntitlements(context.Background(), validConfig(), validSecrets(), ""); err == nil {
		t.Fatal("empty user should error")
	}
}

func TestProvisionRevoke_RejectMissing(t *testing.T) {
	c := New()
	if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{ResourceExternalID: "1"}); err == nil {
		t.Error("provision should require user id")
	}
	if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{UserExternalID: "1"}); err == nil {
		t.Error("revoke should require board id")
	}
}

// TestProvisionRevoke_RejectsNonNumericIDs ensures we reject any input
// that isn't a positive integer before it reaches the GraphQL query
// string. This is the regression test for the GraphQL-injection finding
// (`42) { id } } mutation { delete_board(board_id: 99` style payloads).
func TestProvisionRevoke_RejectsNonNumericIDs(t *testing.T) {
	c := New()
	injection := "42) { id } } mutation { delete_board(board_id: 99"
	cases := []access.AccessGrant{
		{UserExternalID: injection, ResourceExternalID: "42"},
		{UserExternalID: "7", ResourceExternalID: injection},
		{UserExternalID: "abc", ResourceExternalID: "42"},
		{UserExternalID: "7", ResourceExternalID: "0x2a"},
		{UserExternalID: "-1", ResourceExternalID: "42"},
		{UserExternalID: "7", ResourceExternalID: "0"},
	}
	for i, g := range cases {
		if err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), g); err == nil {
			t.Errorf("case %d: provision should reject non-numeric id, grant=%+v", i, g)
		}
		if err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), g); err == nil {
			t.Errorf("case %d: revoke should reject non-numeric id, grant=%+v", i, g)
		}
	}
}
