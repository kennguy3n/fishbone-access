package wasabi

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

func validConfig() map[string]interface{} { return map[string]interface{}{} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id":     "AKAAAA1234bbbbCCCC",
		"secret_access_key": "skAAAA1234bbbbCCCC",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing keys")
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Errorf("expected SigV4 auth, got %q", r.Header.Get("Authorization"))
		}
		_ = r.ParseForm()
		if r.PostForm.Get("Action") != "ListUsers" {
			t.Errorf("Action = %q", r.PostForm.Get("Action"))
		}
		if calls == 1 {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<ListUsersResponse><ListUsersResult><IsTruncated>true</IsTruncated><Marker>m2</Marker><Users><member><UserName>alice</UserName><UserId>U1</UserId><Arn>arn:1</Arn><Path>/</Path><CreateDate>2026-01-01</CreateDate></member><member><UserName>bob</UserName><UserId>U2</UserId><Arn>arn:2</Arn><Path>/</Path><CreateDate>2026-01-02</CreateDate></member></Users></ListUsersResult></ListUsersResponse>`))
			return
		}
		if r.PostForm.Get("Marker") != "m2" {
			t.Errorf("Marker = %q", r.PostForm.Get("Marker"))
		}
		_, _ = w.Write([]byte(`<ListUsersResponse><ListUsersResult><IsTruncated>false</IsTruncated><Users><member><UserName>carol</UserName><UserId>U3</UserId><Arn>arn:3</Arn><Path>/</Path><CreateDate>2026-01-03</CreateDate></member></Users></ListUsersResult></ListUsersResponse>`))
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
	short, _ := md["access_key_id_short"].(string)
	if short == "" || strings.Contains(short, "AAAA1234") {
		t.Errorf("access_key_id_short = %q", short)
	}
}
