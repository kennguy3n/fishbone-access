package iamcore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/config"
)

// fakeIAMCore stands in for iam-core: it mints a token and records management
// calls. Used to exercise the ManagementClient without a real iam-core.
type fakeIAMCore struct {
	tokenIssued int
	lastAuth    string
	blocked     []string
}

func (f *fakeIAMCore) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		f.tokenIssued++
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-abc", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/management/users", func(w http.ResponseWriter, r *http.Request) {
		f.lastAuth = r.Header.Get("Authorization")
		var u User
		_ = json.NewDecoder(r.Body).Decode(&u)
		u.ID = "iam-user-1"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(u)
	})
	mux.HandleFunc("/api/v1/management/users/iam-user-1/block", func(w http.ResponseWriter, _ *http.Request) {
		f.blocked = append(f.blocked, "iam-user-1")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/v1/management/connections", func(w http.ResponseWriter, r *http.Request) {
		var c Connection
		_ = json.NewDecoder(r.Body).Decode(&c)
		c.ID = "conn-1"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(c)
	})
	return mux
}

func newTestClient(t *testing.T) (*ManagementClient, *fakeIAMCore) {
	t.Helper()
	fake := &fakeIAMCore{}
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)
	cfg := config.IAMCoreConfig{
		Issuer:       srv.URL,
		ClientID:     "shieldnet-access",
		ClientSecret: "shh",
		Audience:     "mgmt",
	}
	return NewManagementClient(cfg, srv.Client()), fake
}

func TestCreateUserMintsAndCachesToken(t *testing.T) {
	c, fake := newTestClient(t)
	u, err := c.CreateUser(context.Background(), User{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID != "iam-user-1" {
		t.Errorf("user id = %q", u.ID)
	}
	if fake.lastAuth != "Bearer tok-abc" {
		t.Errorf("auth header = %q", fake.lastAuth)
	}
	// Second call should reuse the cached token (no new mint).
	if _, err := c.CreateUser(context.Background(), User{Email: "b@example.com"}); err != nil {
		t.Fatalf("CreateUser 2: %v", err)
	}
	if fake.tokenIssued != 1 {
		t.Errorf("tokenIssued = %d, want 1 (token should be cached)", fake.tokenIssued)
	}
}

func TestBlockUser(t *testing.T) {
	c, fake := newTestClient(t)
	if err := c.BlockUser(context.Background(), "iam-user-1"); err != nil {
		t.Fatalf("BlockUser: %v", err)
	}
	if len(fake.blocked) != 1 {
		t.Errorf("blocked = %v", fake.blocked)
	}
}

func TestCreateConnection(t *testing.T) {
	c, _ := newTestClient(t)
	conn, err := c.CreateConnection(context.Background(), Connection{Name: "okta-prod", Strategy: "oidc"})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	if conn.ID != "conn-1" {
		t.Errorf("conn id = %q", conn.ID)
	}
}
