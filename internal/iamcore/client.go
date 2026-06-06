package iamcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/kennguy3n/fishbone-access/internal/config"
)

// ManagementClient calls iam-core's audience-restricted Management API
// (/api/v1/management/*) and Connections API. It authenticates with a
// client_credentials access token minted at /oauth2/token, cached until just
// before expiry. This is the bridge ShieldNet Access uses to provision users
// into iam-core and to configure SSO connections for customer IdPs.
type ManagementClient struct {
	httpc     *http.Client
	tokenURL  string
	mgmtBase  string
	clientID  string
	clientSec string
	audience  string

	// mu guards the cached token. It is held only for the (lock-free) in-memory
	// read/write of token/tokenExp, never across the HTTP round-trip — the
	// network call happens inside sf.Do so concurrent callers that need a fresh
	// token share a single in-flight mint instead of serializing on the mutex.
	mu       sync.RWMutex
	token    string
	tokenExp time.Time
	sf       singleflight.Group
}

// NewManagementClient builds a client from configuration. It performs no I/O.
func NewManagementClient(cfg config.IAMCoreConfig, httpc *http.Client) *ManagementClient {
	if httpc == nil {
		httpc = &http.Client{Timeout: 15 * time.Second}
	}
	return &ManagementClient{
		httpc:     httpc,
		tokenURL:  strings.TrimRight(cfg.Issuer, "/") + "/oauth2/token",
		mgmtBase:  cfg.ResolvedManagementBaseURL(),
		clientID:  cfg.ClientID,
		clientSec: cfg.ClientSecret,
		audience:  cfg.Audience,
	}
}

// User is the subset of an iam-core management user record ShieldNet Access
// reads and writes.
type User struct {
	ID      string `json:"user_id,omitempty"`
	Email   string `json:"email"`
	Name    string `json:"name,omitempty"`
	Blocked bool   `json:"blocked,omitempty"`
}

// Connection mirrors the iam-core Connections API create payload. Strategy is a
// catalog slug: google-oauth2, microsoft, oidc (generic, used for Okta), zoho,
// github, ... See docs/iam-core-integration.md.
type Connection struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name"`
	Strategy string         `json:"strategy"`
	Options  map[string]any `json:"options,omitempty"`
	Enabled  bool           `json:"enabled,omitempty"`
}

// accessToken returns a valid client_credentials access token, minting a fresh
// one when the cache is empty or within 30s of expiry.
//
// The hot path (a still-valid cached token) takes only a read lock and never
// touches the network, so management calls don't serialize on each other. When
// a refresh is needed the HTTP round-trip runs inside a singleflight group keyed
// on "token": concurrent callers collapse into one mint and share its result
// instead of stampeding the token endpoint or blocking on a write lock held
// across the network.
func (c *ManagementClient) accessToken(ctx context.Context) (string, error) {
	if tok, ok := c.cachedToken(); ok {
		return tok, nil
	}

	v, err, _ := c.sf.Do("token", func() (any, error) {
		// Re-check under the singleflight: a concurrent caller may have already
		// refreshed while we waited to become the leader.
		if tok, ok := c.cachedToken(); ok {
			return tok, nil
		}
		return c.mintToken(ctx)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// cachedToken returns the cached token if it is present and not within 30s of
// expiry.
func (c *ManagementClient) cachedToken() (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token != "" && time.Until(c.tokenExp) > 30*time.Second {
		return c.token, true
	}
	return "", false
}

// mintToken performs the client_credentials grant and stores the result. It is
// only ever called from inside the singleflight, so at most one mint is in
// flight at a time.
func (c *ManagementClient) mintToken(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSec},
	}
	if c.audience != "" {
		form.Set("audience", c.audience)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("iamcore: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("iamcore: token endpoint status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("iamcore: decode token: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("iamcore: empty access_token in token response")
	}
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 300
	}
	c.mu.Lock()
	c.token = tr.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(ttl) * time.Second)
	c.mu.Unlock()
	return tr.AccessToken, nil
}

func (c *ManagementClient) do(ctx context.Context, method, path string, body, out any) error {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.mgmtBase+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("iamcore: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("iamcore: %s %s status %d: %s", method, path, resp.StatusCode, string(snippet))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// CreateUser provisions a user in iam-core (POST /api/v1/management/users).
func (c *ManagementClient) CreateUser(ctx context.Context, u User) (*User, error) {
	var created User
	if err := c.do(ctx, http.MethodPost, "/api/v1/management/users", u, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

// GetUser reads a user by id (GET /api/v1/management/users/{user_id}).
func (c *ManagementClient) GetUser(ctx context.Context, userID string) (*User, error) {
	var u User
	if err := c.do(ctx, http.MethodGet, "/api/v1/management/users/"+url.PathEscape(userID), nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// BlockUser deactivates a user (POST .../users/{user_id}/block). This is the
// SCIM-bridge "deprovision" path — iam-core has no SCIM inbound, so a SCIM
// delete/disable maps onto block.
func (c *ManagementClient) BlockUser(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/management/users/"+url.PathEscape(userID)+"/block", nil, nil)
}

// UnblockUser reactivates a user (POST .../users/{user_id}/unblock).
func (c *ManagementClient) UnblockUser(ctx context.Context, userID string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/management/users/"+url.PathEscape(userID)+"/unblock", nil, nil)
}

// CreateConnection configures an SSO connection in iam-core
// (POST /api/v1/management/connections). This replaces the Keycloak SSO
// federation path inherited from the reference platform.
func (c *ManagementClient) CreateConnection(ctx context.Context, conn Connection) (*Connection, error) {
	var created Connection
	if err := c.do(ctx, http.MethodPost, "/api/v1/management/connections", conn, &created); err != nil {
		return nil, err
	}
	return &created, nil
}
