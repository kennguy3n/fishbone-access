// Package paypal implements the access.AccessConnector contract for the
// PayPal partner-merchant integrations API.
//
// PayPal does not expose a public REST API for "list dashboard team
// members". The closest equivalent for partner-managed workflows is
// /v1/customer/partners/{partner_id}/merchant-integrations, which lists
// the merchant accounts a partner has onboarded. This connector treats
// each merchant integration as an IdentityTypeServiceAccount (one row
// per onboarded merchant), the same approach the Stripe connector uses
// for Connect accounts.
//
// Auth uses OAuth2 client_credentials: the connector exchanges the
// configured client_id + secret for a short-lived bearer token via
// /v1/oauth2/token before each sync.
package paypal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	ProviderName = "paypal"
	pageSize     = 50

	// tokenRefreshMargin is subtracted from the OAuth2 token lifetime so a
	// cached token is refreshed slightly before PayPal would reject it,
	// avoiding a 401 on a request that races the expiry boundary (e.g. the
	// last page of a long sync).
	tokenRefreshMargin = 60 * time.Second
)

var ErrNotImplemented = fmt.Errorf("paypal: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	PartnerID string `json:"partner_id"`
	Sandbox   bool   `json:"sandbox"`
}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// cachedToken is an OAuth2 bearer token together with the instant at which
// it should be considered stale (the real expiry minus tokenRefreshMargin).
type cachedToken struct {
	token  string
	expiry time.Time
}

// tokenCall represents an in-flight mint shared by every goroutine that asks
// for the same credentials' token while one request is already outstanding.
type tokenCall struct {
	done  chan struct{}
	token string
	err   error
}

type PayPalAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string

	// tokenCache memoizes minted OAuth2 tokens keyed by (base URL +
	// credentials) so repeated calls — including per-page calls within a
	// single sync — reuse a live token instead of minting a new one on
	// every request. The connector is registered as a process-wide
	// singleton shared across tenants, so the cache MUST be keyed by
	// credentials to avoid handing one tenant's token to another.
	//
	// tokenInflight deduplicates concurrent cache misses for the same key:
	// the first goroutine mints while the rest wait on the shared result,
	// preventing a thundering herd on /v1/oauth2/token when many syncs start
	// at once. Both maps are guarded by tokenMu.
	tokenMu       sync.Mutex
	tokenCache    map[string]cachedToken
	tokenInflight map[string]*tokenCall
}

func New() *PayPalAccessConnector { return &PayPalAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("paypal: config is nil")
	}
	var cfg Config
	if v, ok := raw["partner_id"].(string); ok {
		cfg.PartnerID = v
	}
	if v, ok := raw["sandbox"].(bool); ok {
		cfg.Sandbox = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("paypal: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["client_id"].(string); ok {
		s.ClientID = v
	}
	if v, ok := raw["client_secret"].(string); ok {
		s.ClientSecret = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.PartnerID) == "" {
		return errors.New("paypal: partner_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("paypal: client_id is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return errors.New("paypal: client_secret is required")
	}
	return nil
}

func (c *PayPalAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *PayPalAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if cfg.Sandbox {
		return "https://api-m.sandbox.paypal.com"
	}
	return "https://api-m.paypal.com"
}

// doHTTP routes the request through the injected test httpClient when
// present, otherwise through the shared RetryClient so production
// traffic reuses the connection pool (keep-alive, TLS sessions) and
// gets the 429/5xx retry-with-jitter policy.
func (c *PayPalAccessConnector) doHTTP(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	return sharedRetryClient.Do(req.Context(), req)
}

// sharedRetryClient is a package-level singleton so the underlying
// *http.Client connection pool is reused across requests rather than
// rebuilt per call.
var sharedRetryClient = httputil.NewRetryClient(30 * time.Second)

func (c *PayPalAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

// tokenCacheKey derives a stable, non-reversible cache key from the base
// URL and credentials. Hashing keeps the raw client secret out of the
// in-memory map keys.
func tokenCacheKey(baseURL string, s Secrets) string {
	sum := sha256.Sum256([]byte(baseURL + "\x00" + strings.TrimSpace(s.ClientID) + "\x00" + strings.TrimSpace(s.ClientSecret)))
	return hex.EncodeToString(sum[:])
}

// accessToken returns a valid OAuth2 bearer token, reusing a cached token
// when one is still within its lifetime and minting a fresh one otherwise.
// It is safe for concurrent use. Because callers invoke it per request
// (e.g. once per page of a sync), a token that approaches expiry mid-sync
// is transparently refreshed rather than producing a 401 partway through.
func (c *PayPalAccessConnector) accessToken(ctx context.Context, cfg Config, secrets Secrets) (string, error) {
	key := tokenCacheKey(c.baseURL(cfg), secrets)
	now := time.Now()

	c.tokenMu.Lock()
	if ct, ok := c.tokenCache[key]; ok && now.Before(ct.expiry) {
		tok := ct.token
		c.tokenMu.Unlock()
		return tok, nil
	}
	// A mint for this key is already in flight: wait for its result instead
	// of issuing a duplicate token request.
	if call, ok := c.tokenInflight[key]; ok {
		c.tokenMu.Unlock()
		select {
		case <-call.done:
			return call.token, call.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	// Become the leader for this key.
	call := &tokenCall{done: make(chan struct{})}
	if c.tokenInflight == nil {
		c.tokenInflight = make(map[string]*tokenCall)
	}
	c.tokenInflight[key] = call
	c.tokenMu.Unlock()

	tok, ttl, err := c.mintToken(ctx, cfg, secrets)

	c.tokenMu.Lock()
	// Only cache when PayPal reports a lifetime longer than the refresh
	// margin. Without a known expiry (ttl == 0) we cannot tell when the token
	// goes stale; and when ttl <= tokenRefreshMargin we could not honor the
	// margin anyway, so caching would risk serving a token in the window where
	// it is already (or about to be) rejected. In both cases we conservatively
	// re-mint on the next call rather than cache a token we cannot safely
	// guard, mirroring the ttl == 0 skip.
	if err == nil && ttl > tokenRefreshMargin {
		expiry := now.Add(ttl - tokenRefreshMargin)
		if c.tokenCache == nil {
			c.tokenCache = make(map[string]cachedToken)
		}
		c.tokenCache[key] = cachedToken{token: tok, expiry: expiry}
	}
	// Publish the result, release waiters, and clear the in-flight marker
	// all under the same lock. Doing this atomically closes the window where
	// a newcomer could observe neither a cached token (mint failed, so none
	// stored) nor an in-flight entry (already deleted) and spuriously start a
	// second mint. Closing the channel while holding tokenMu is safe because
	// waiters always release the lock before selecting on call.done.
	call.token, call.err = tok, err
	close(call.done)
	delete(c.tokenInflight, key)
	c.tokenMu.Unlock()

	return tok, err
}

// mintToken performs the OAuth2 client_credentials exchange and returns the
// bearer token together with its lifetime (0 when PayPal omits expires_in).
func (c *PayPalAccessConnector) mintToken(ctx context.Context, cfg Config, secrets Secrets) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(cfg)+"/v1/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.ClientID) + ":" + strings.TrimSpace(secrets.ClientSecret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	resp, err := c.doHTTP(req)
	if err != nil {
		return "", 0, fmt.Errorf("paypal: oauth2 token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("paypal: oauth2 token status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("paypal: decode token: %w", err)
	}
	if out.AccessToken == "" {
		return "", 0, errors.New("paypal: empty access_token in oauth2 response")
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (c *PayPalAccessConnector) newRequest(ctx context.Context, token, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

func (c *PayPalAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doHTTP(req)
	if err != nil {
		return nil, fmt.Errorf("paypal: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("paypal: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *PayPalAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("paypal: connect oauth2: %w", err)
	}
	probe := fmt.Sprintf("%s/v1/customer/partners/%s/merchant-integrations?page=1&page_size=1", c.baseURL(cfg), url.PathEscape(strings.TrimSpace(cfg.PartnerID)))
	req, err := c.newRequest(ctx, token, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("paypal: connect probe: %w", err)
	}
	return nil
}

func (c *PayPalAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type paypalMerchant struct {
	MerchantID         string `json:"merchant_id"`
	TrackingID         string `json:"tracking_id"`
	PrimaryEmail       string `json:"primary_email"`
	PaymentsReceivable bool   `json:"payments_receivable"`
	OAuthIntegrations  []struct {
		IntegrationType string `json:"integration_type"`
	} `json:"oauth_integrations"`
}

type paypalListResponse struct {
	MerchantIntegrations []paypalMerchant `json:"merchant_integrations"`
	TotalItems           int              `json:"total_items"`
}

func (c *PayPalAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *PayPalAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 1 {
			page = 1
		}
	}
	base := c.baseURL(cfg)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Fetch the token per page (cached) so a long, multi-page sync
		// transparently refreshes the bearer as it approaches expiry
		// instead of carrying one token that could go stale mid-sync.
		token, err := c.accessToken(ctx, cfg, secrets)
		if err != nil {
			return err
		}
		path := fmt.Sprintf("%s/v1/customer/partners/%s/merchant-integrations?page=%d&page_size=%d", base, url.PathEscape(strings.TrimSpace(cfg.PartnerID)), page, pageSize)
		req, err := c.newRequest(ctx, token, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp paypalListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("paypal: decode merchants: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.MerchantIntegrations))
		for _, m := range resp.MerchantIntegrations {
			display := m.TrackingID
			if display == "" {
				display = m.MerchantID
			}
			status := "active"
			if !m.PaymentsReceivable {
				status = "restricted"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.MerchantID,
				Type:        access.IdentityTypeServiceAccount,
				DisplayName: display,
				Email:       m.PrimaryEmail,
				Status:      status,
			})
		}
		next := ""
		if (page)*pageSize < resp.TotalItems && len(resp.MerchantIntegrations) > 0 {
			next = fmt.Sprintf("%d", page+1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker PayPal SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *PayPalAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *PayPalAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":            ProviderName,
		"auth_type":           "oauth2_client_credentials",
		"client_id_short":     shortToken(secrets.ClientID),
		"client_secret_short": shortToken(secrets.ClientSecret),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	// Never echo a token verbatim. Production tokens are far longer than
	// 8 chars, but a misconfigured/test token must not leak in full
	// through GetCredentialsMetadata, so short tokens are fully masked.
	if len(t) <= 8 {
		return "***"
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*PayPalAccessConnector)(nil)
