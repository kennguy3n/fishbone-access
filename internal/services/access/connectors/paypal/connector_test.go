package paypal

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

func validConfig() map[string]interface{} { return map[string]interface{}{"partner_id": "PARTNER123"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"client_id": "ppCID1234bbbbCCCC", "client_secret": "ppCS1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing partner_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{"client_id": "x"}); err == nil {
		t.Error("missing client_secret")
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
	listCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth2/token":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				t.Errorf("expected Basic auth on token")
			}
			b, _ := json.Marshal(map[string]interface{}{"access_token": "tok-xyz", "token_type": "Bearer", "expires_in": 32400})
			_, _ = w.Write(b)
		default:
			listCalls++
			if r.Header.Get("Authorization") != "Bearer tok-xyz" {
				t.Errorf("expected Bearer tok-xyz, got %q", r.Header.Get("Authorization"))
			}
			if !strings.HasPrefix(r.URL.Path, "/v1/customer/partners/PARTNER123/merchant-integrations") {
				t.Errorf("path = %q", r.URL.Path)
			}
			body := map[string]interface{}{"merchant_integrations": []map[string]interface{}{}, "total_items": pageSize + 1}
			page := r.URL.Query().Get("page")
			if listCalls == 1 && page != "1" {
				t.Errorf("page = %q", page)
			}
			if listCalls == 1 {
				items := make([]map[string]interface{}, 0, pageSize)
				for i := 0; i < pageSize; i++ {
					items = append(items, map[string]interface{}{"merchant_id": fmt.Sprintf("M%d", i), "tracking_id": fmt.Sprintf("biz-%d", i), "primary_email": fmt.Sprintf("m%d@x.com", i), "payments_receivable": true})
				}
				body["merchant_integrations"] = items
			} else {
				body["merchant_integrations"] = []map[string]interface{}{{"merchant_id": "Mlast", "tracking_id": "", "primary_email": "last@x.com", "payments_receivable": false}}
			}
			b, _ := json.Marshal(body)
			_, _ = w.Write(b)
		}
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
	if listCalls != 2 {
		t.Fatalf("listCalls = %d", listCalls)
	}
	if got[len(got)-1].Status != "restricted" {
		t.Errorf("status = %q; want restricted", got[len(got)-1].Status)
	}
	if got[0].Type != access.IdentityTypeServiceAccount {
		t.Errorf("type = %q; want service_account (PayPal merchant integrations are merchant businesses)", got[0].Type)
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
	short, _ := md["client_id_short"].(string)
	if short == "" || strings.Contains(short, "CID1234") {
		t.Errorf("client_id_short = %q", short)
	}
	short2, _ := md["client_secret_short"].(string)
	if short2 == "" || strings.Contains(short2, "CS1234") {
		t.Errorf("client_secret_short = %q", short2)
	}
}
