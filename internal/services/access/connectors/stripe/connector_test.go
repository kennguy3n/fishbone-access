package stripe

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
	return map[string]interface{}{"secret_key": "sk_test_AAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing key")
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
		if r.URL.Path != "/v1/accounts" {
			t.Errorf("path = %q; want /v1/accounts", r.URL.Path)
		}
		if calls == 1 {
			data := []map[string]interface{}{
				{
					"id":               "acct_1",
					"email":            "a@x.com",
					"business_profile": map[string]interface{}{"name": "Acme Inc."},
					"charges_enabled":  true,
					"payouts_enabled":  true,
				},
				{
					"id":               "acct_2",
					"email":            "b@x.com",
					"business_profile": map[string]interface{}{"name": "Beta Co."},
					"charges_enabled":  true,
					"payouts_enabled":  false,
				},
			}
			b, _ := json.Marshal(map[string]interface{}{
				"object":   "list",
				"has_more": true,
				"data":     data,
			})
			_, _ = w.Write(b)
			return
		}
		if r.URL.Query().Get("starting_after") != "acct_2" {
			t.Errorf("starting_after = %q", r.URL.Query().Get("starting_after"))
		}
		_, _ = fmt.Fprintf(w, `{"object":"list","has_more":false,"data":[{"id":"acct_3","email":"c@x.com","charges_enabled":true,"payouts_enabled":true}]}`)
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
	if len(got) != 3 {
		t.Fatalf("len = %d", len(got))
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	for _, id := range got {
		if id.Type != access.IdentityTypeServiceAccount {
			t.Errorf("identity %q type = %q; want service_account (Stripe Connect accounts are merchant businesses, not human users)", id.ExternalID, id.Type)
		}
	}
	if got[0].DisplayName != "Acme Inc." {
		t.Errorf("acct_1 display = %q; want Acme Inc.", got[0].DisplayName)
	}
	if got[1].Status != "restricted" {
		t.Errorf("acct_2 status = %q; want restricted (payouts_enabled=false)", got[1].Status)
	}
	if got[2].Status != "active" {
		t.Errorf("acct_3 status = %q; want active", got[2].Status)
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
	short, _ := md["key_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("key_short = %q", short)
	}
}
