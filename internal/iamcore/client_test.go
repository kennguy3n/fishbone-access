package iamcore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestAccessTokenDetachesCallerCancellation locks the singleflight context fix:
// the shared token mint must NOT be tied to the triggering caller's context. A
// caller whose context is already cancelled still gets a token, because the
// mint runs on a detached context (context.WithoutCancel). With the old code
// (passing the caller's ctx straight into the singleflight) this would fail
// with context.Canceled — and in the concurrent case that cancellation would
// cascade to every other waiter sharing the same singleflight round.
func TestAccessTokenDetachesCallerCancellation(t *testing.T) {
	c, fake := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller has already given up before the mint runs

	tok, err := c.accessToken(ctx)
	if err != nil {
		t.Fatalf("accessToken with cancelled caller ctx: %v (mint should run on a detached context)", err)
	}
	if tok != "tok-abc" {
		t.Errorf("token = %q, want tok-abc", tok)
	}
	if fake.tokenIssued != 1 {
		t.Errorf("tokenIssued = %d, want 1", fake.tokenIssued)
	}
}

// TestStaleTokenInvalidatedAndRetriedOn401 locks the self-healing behaviour:
// when iam-core rejects a cached token with 401 (server-side revocation or key
// rotation before our client-side TTL), the client drops the cached token,
// mints a fresh one, and retries the call once so it succeeds — instead of
// reusing the dead token for the rest of its lifetime. The fresh token must
// then be cached so subsequent calls don't re-mint.
func TestStaleTokenInvalidatedAndRetriedOn401(t *testing.T) {
	var minted atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		n := minted.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("tok-%d", n), "expires_in": 3600,
		})
	})
	mux.HandleFunc("/api/v1/management/users", func(w http.ResponseWriter, r *http.Request) {
		// Reject the first minted token (tok-1) as if it had been revoked;
		// accept any freshly minted one.
		if r.Header.Get("Authorization") == "Bearer tok-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
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

	u, err := c.CreateUser(context.Background(), User{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("CreateUser should self-heal after a 401: %v", err)
	}
	if u.ID != "iam-user-1" {
		t.Errorf("user id = %q", u.ID)
	}
	if got := minted.Load(); got != 2 {
		t.Errorf("tokens minted = %d, want 2 (stale token invalidated, fresh one minted)", got)
	}
	// The fresh token must now be cached: a follow-up call mints nothing new.
	if _, err := c.CreateUser(context.Background(), User{Email: "b@example.com"}); err != nil {
		t.Fatalf("CreateUser 2: %v", err)
	}
	if got := minted.Load(); got != 2 {
		t.Errorf("tokens minted after 2nd call = %d, want 2 (fresh token should be cached)", got)
	}
}

// TestPersistent401RetriesOnce verifies the retry is bounded: if every token is
// rejected (the credentials themselves are bad, not a stale cache), the client
// retries exactly once and then surfaces the 401, rather than looping forever.
func TestPersistent401RetriesOnce(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/management/users", func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewManagementClient(config.IAMCoreConfig{
		Issuer: srv.URL, ClientID: "id", ClientSecret: "sec", Audience: "mgmt",
	}, srv.Client())

	if _, err := c.CreateUser(context.Background(), User{Email: "a@example.com"}); err == nil {
		t.Fatal("CreateUser should surface the 401 error after one retry")
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("management calls = %d, want 2 (initial attempt + one retry)", got)
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

// TestConnectionEnabledAlwaysSerialized guards against re-introducing
// `omitempty` on Connection.Enabled: a meaningful request bool must always be
// sent, otherwise enabled=false is silently dropped and iam-core applies its
// own default (creating a connection in the wrong state).
func TestConnectionEnabledAlwaysSerialized(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		want    string
	}{
		{"enabled", true, `"enabled":true`},
		{"disabled", false, `"enabled":false`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(Connection{Name: "n", Strategy: "oidc", Enabled: tc.enabled})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(b), tc.want) {
				t.Errorf("payload %s missing %s", b, tc.want)
			}
		})
	}
}
