package iamcore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// TestConcurrentCallersCollapseTokenMint verifies the singleflight behaviour:
// when many management calls race with an empty token cache, exactly ONE token
// is minted (the concurrent callers share the single in-flight fetch) instead
// of each call stampeding the token endpoint. The token handler sleeps to widen
// the race window so a regression (e.g. dropping singleflight) reliably mints
// more than one token. Run with -race to also catch unsynchronised access to
// the cached token.
func TestConcurrentCallersCollapseTokenMint(t *testing.T) {
	var minted atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		minted.Add(1)
		time.Sleep(50 * time.Millisecond) // widen the window for collapse
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-xyz", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/management/users", func(w http.ResponseWriter, r *http.Request) {
		var u User
		_ = json.NewDecoder(r.Body).Decode(&u)
		u.ID = "iam-user-1"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(u)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := NewManagementClient(config.IAMCoreConfig{
		Issuer: srv.URL, ClientID: "id", ClientSecret: "sec", Audience: "mgmt",
	}, srv.Client())

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := c.CreateUser(context.Background(), User{Email: "x@example.com"}); err != nil {
				t.Errorf("CreateUser: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := minted.Load(); got != 1 {
		t.Fatalf("token minted %d times, want 1 (singleflight should collapse concurrent refreshes)", got)
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
