package discord

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

func validConfig() map[string]interface{} { return map[string]interface{}{"guild_id": "1234567890"} }
func validSecrets() map[string]interface{} {
	return map[string]interface{}{"bot_token": "dscdAAAA1234bbbbCCCC"}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissing(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{}, validSecrets()); err == nil {
		t.Error("missing guild_id")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing bot_token")
	}
}

func TestValidate_RejectsNonNumericGuild(t *testing.T) {
	c := New()
	for _, bad := range []string{"abc", "12-34", "12 34", "1234/5"} {
		if err := c.Validate(context.Background(), map[string]interface{}{"guild_id": bad}, validSecrets()); err == nil {
			t.Errorf("expected error for guild_id %q", bad)
		}
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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bot ") {
			t.Errorf("expected Bot auth")
		}
		if r.URL.Path != "/api/v10/guilds/1234567890/members" {
			t.Errorf("path = %q", r.URL.Path)
		}
		after := r.URL.Query().Get("after")
		var items []map[string]interface{}
		if calls == 1 {
			if after != "" {
				t.Errorf("first call after = %q", after)
			}
			for i := 0; i < pageSize; i++ {
				items = append(items, map[string]interface{}{
					"user":  map[string]interface{}{"id": fmt.Sprintf("%d", 10000+i), "username": fmt.Sprintf("u%d", i), "global_name": "User"},
					"roles": []string{"role1"},
				})
			}
		} else {
			expected := fmt.Sprintf("%d", 10000+pageSize-1)
			if after != expected {
				t.Errorf("after = %q want %q", after, expected)
			}
			items = []map[string]interface{}{{
				"user":    map[string]interface{}{"id": "99", "username": "bot", "bot": true},
				"pending": true,
			}}
		}
		b, _ := json.Marshal(items)
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
	if len(got) != pageSize+1 || calls != 2 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
	if got[len(got)-1].Type != access.IdentityTypeServiceAccount {
		t.Errorf("type = %q", got[len(got)-1].Type)
	}
	if got[len(got)-1].Status != "pending" {
		t.Errorf("status = %q", got[len(got)-1].Status)
	}
}

func TestConnect_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
