package heroku

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
	return map[string]interface{}{"api_key": "k-1234567890abcdef"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingKey(t *testing.T) {
	if err := New().Validate(context.Background(), nil, map[string]interface{}{}); err == nil {
		t.Error("missing api_key: want error")
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
	if got, err := access.GetAccessConnector(ProviderName); err != nil || got == nil {
		t.Fatalf("GetAccessConnector: %v %v", got, err)
	}
}

func TestSync_TeamMembers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/teams/uney/members") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"id":"m1","email":"a@b.com","role":"admin","user":{"id":"u1","email":"a@b.com","name":"Alice"}}]`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), map[string]interface{}{"team_name": "uney"}, validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 1 || got[0].ExternalID != "u1" {
		t.Fatalf("got = %+v", got)
	}
}

func TestSync_AccountFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"u1","email":"solo@uney.com","name":"Solo"}`))
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
	if len(got) != 1 || got[0].Email != "solo@uney.com" {
		t.Fatalf("got = %+v", got)
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), nil, validSecrets()); err == nil {
		t.Error("Connect: want error")
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["token_short"] == "k-1234567890abcdef" {
		t.Error("token_short should be shortened or redacted")
	}
	if !strings.Contains(md["token_short"].(string), "...") {
		t.Errorf("token_short = %v; want shortened form", md["token_short"])
	}
}
