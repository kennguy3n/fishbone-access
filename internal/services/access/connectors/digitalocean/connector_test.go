package digitalocean

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
	return map[string]interface{}{"api_token": "dop_v1_xxxxx"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MissingToken(t *testing.T) {
	if err := New().Validate(context.Background(), nil, map[string]interface{}{}); err == nil {
		t.Error("missing api_token: want error")
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
	got, err := access.GetAccessConnector(ProviderName)
	if err != nil {
		t.Fatalf("GetAccessConnector: %v", err)
	}
	if _, ok := got.(*DigitalOceanAccessConnector); !ok {
		t.Fatalf("type = %T", got)
	}
}

func TestConnect_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dop_v1_xxxxx" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"account":{"uuid":"u1","email":"a@b.com","status":"active"}}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), nil, validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
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
	if err := c.Connect(context.Background(), nil, validSecrets()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Connect err = %v; want 401", err)
	}
}

func TestSyncIdentities_TeamMembers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"members":[{"uuid":"u1","email":"a@b.com","first_name":"A","last_name":"B","status":"active"}],
			"meta":{"total":1}
		}`))
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
	if len(got) != 1 || got[0].Email != "a@b.com" {
		t.Fatalf("got = %+v", got)
	}
}

func TestSyncIdentities_FallsBackToAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/team/members") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"account":{"uuid":"u1","email":"solo@uney.com","status":"active"}}`))
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

func TestSyncIdentities_PaginatesAcrossPages(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			if !strings.Contains(r.URL.RawQuery, "per_page=50") {
				t.Errorf("page1 query = %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{
				"members":[{"uuid":"u1","email":"a@b.com","first_name":"A","status":"active"}],
				"meta":{"total":2},
				"links":{"pages":{"next":"https://example.com/v2/team/members?per_page=50&page=2"}}
			}`))
		case 2:
			if !strings.Contains(r.URL.RawQuery, "page=2") {
				t.Errorf("page2 query = %q; want page=2", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{
				"members":[{"uuid":"u2","email":"c@d.com","first_name":"C","status":"active"}],
				"meta":{"total":2}
			}`))
		default:
			t.Fatalf("unexpected request #%d to %s", calls, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	var lastNext string
	err := c.SyncIdentities(context.Background(), nil, validSecrets(), "", func(b []*access.Identity, next string) error {
		got = append(got, b...)
		lastNext = next
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 round trips, got %d", calls)
	}
	if len(got) != 2 || got[0].Email != "a@b.com" || got[1].Email != "c@d.com" {
		t.Fatalf("got = %+v", got)
	}
	if lastNext != "" {
		t.Errorf("final next = %q; want empty", lastNext)
	}
}

func TestGetCredentialsMetadata_RedactsToken(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["token_short"] == "dop_v1_xxxxx" {
		t.Error("token_short must not include the full token")
	}
}
