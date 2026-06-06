package vercel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{"api_token": "tok-1234567890abc"}
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
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSync_TeamMembers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"members":[{"uid":"u1","email":"a@b.com","name":"Alice","username":"alice","role":"OWNER","confirmed":true}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), map[string]interface{}{"team_id": "team_x"}, validSecrets(), "", func(b []*access.Identity, _ string) error {
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

func TestSync_UserFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"user":{"id":"u1","email":"solo@uney.com","name":"Solo","username":"solo"}}`))
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
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
}

func TestSync_PaginatesAcrossPages(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			if strings.Contains(r.URL.RawQuery, "until=") {
				t.Errorf("page1 should not have until=, got %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{
				"members":[{"uid":"u1","email":"a@b.com","name":"Alice","username":"alice","role":"OWNER","confirmed":true}],
				"pagination":{"next":"cursor-2"}
			}`))
		case 2:
			if !strings.Contains(r.URL.RawQuery, "until=cursor-2") {
				t.Errorf("page2 query = %q; want until=cursor-2", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{
				"members":[{"uid":"u2","email":"c@d.com","name":"Carol","username":"carol","role":"MEMBER","confirmed":false}]
			}`))
		default:
			t.Fatalf("unexpected request #%d", calls)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	var got []*access.Identity
	var lastNext string
	err := c.SyncIdentities(context.Background(), map[string]interface{}{"team_id": "team_x"}, validSecrets(), "", func(b []*access.Identity, next string) error {
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
	if got[1].Status != "pending" {
		t.Errorf("page2 status = %q; want pending", got[1].Status)
	}
	if lastNext != "" {
		t.Errorf("final next = %q; want empty", lastNext)
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

func TestGetCredentialsMetadata(t *testing.T) {
	md, err := New().GetCredentialsMetadata(context.Background(), nil, validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["token_short"] == "tok-1234567890abc" {
		t.Error("token_short must not be the full token")
	}
	if !strings.Contains(md["token_short"].(string), "...") {
		t.Errorf("token_short = %v; want shortened form", md["token_short"])
	}
}

// TestTeamIDIsPathEscaped verifies CountIdentities/SyncIdentities/Connect
// path-escape the team ID before interpolating it into the URL. A team ID
// containing URL-special characters (e.g. '/' or '#') must be encoded so it
// stays a single path segment; without escaping the '#' starts a fragment
// and the request would be routed to a truncated path.
func TestTeamIDIsPathEscaped(t *testing.T) {
	const teamID = "team/with#weird"
	wantEscaped := "/v2/teams/" + url.PathEscape(teamID) + "/members"
	var gotEscaped string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"members":[{"uid":"u1","email":"a@b.com"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }

	n, err := c.CountIdentities(context.Background(), map[string]interface{}{"team_id": teamID}, validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d; want 1", n)
	}
	if gotEscaped != wantEscaped {
		t.Fatalf("escaped path = %q; want %q (team ID not path-escaped)", gotEscaped, wantEscaped)
	}
}
