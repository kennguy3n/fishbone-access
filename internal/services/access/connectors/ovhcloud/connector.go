// Package ovhcloud implements the access.AccessConnector contract for the
// OVHcloud /me/identity/user API.
package ovhcloud

import (
	"context"
	// gosec G505 false positive: OVHcloud's documented API
	// signature format is $1$<sha1(secret+consumer+method+url+body+ts)>.
	// Protocol requirement, not a cryptographic strength choice.
	"crypto/sha1" // #nosec G505
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "ovhcloud"
)

var ErrNotImplemented = fmt.Errorf("ovhcloud: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Endpoint string `json:"endpoint"`
}

type Secrets struct {
	ApplicationKey    string `json:"application_key"`
	ApplicationSecret string `json:"application_secret"`
	ConsumerKey       string `json:"consumer_key"`
}

type OVHcloudAccessConnector struct {
	httpClient   func() httpDoer
	urlOverride  string
	timeOverride func() time.Time
}

func New() *OVHcloudAccessConnector { return &OVHcloudAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("ovhcloud: config is nil")
	}
	var cfg Config
	if v, ok := raw["endpoint"].(string); ok {
		cfg.Endpoint = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("ovhcloud: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["application_key"].(string); ok {
		s.ApplicationKey = v
	}
	if v, ok := raw["application_secret"].(string); ok {
		s.ApplicationSecret = v
	}
	if v, ok := raw["consumer_key"].(string); ok {
		s.ConsumerKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	ep := strings.TrimSpace(c.Endpoint)
	if ep == "" {
		return errors.New("ovhcloud: endpoint is required (eu, ca, or us)")
	}
	switch ep {
	case "eu", "ca", "us":
		return nil
	}
	return errors.New("ovhcloud: endpoint must be one of eu, ca, us")
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ApplicationKey) == "" {
		return errors.New("ovhcloud: application_key is required")
	}
	if strings.TrimSpace(s.ApplicationSecret) == "" {
		return errors.New("ovhcloud: application_secret is required")
	}
	if strings.TrimSpace(s.ConsumerKey) == "" {
		return errors.New("ovhcloud: consumer_key is required")
	}
	return nil
}

func (c *OVHcloudAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *OVHcloudAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	switch cfg.Endpoint {
	case "ca":
		return "https://ca.api.ovh.com/1.0"
	case "us":
		return "https://api.us.ovhcloud.com/1.0"
	}
	return "https://api.ovh.com/1.0"
}

func (c *OVHcloudAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *OVHcloudAccessConnector) now() time.Time {
	if c.timeOverride != nil {
		return c.timeOverride()
	}
	return time.Now()
}

// signOVH computes the OVH signature: $1$<sha1(secret+consumer+method+url+body+ts)>.
func signOVH(applicationSecret, consumerKey, method, fullURL, body string, ts int64) string {
	// gosec G401: SHA-1 is the OVHcloud protocol signature.
	h := sha1.New() // #nosec G401
	_, _ = fmt.Fprintf(h, "%s+%s+%s+%s+%s+%d", applicationSecret, consumerKey, method, fullURL, body, ts)
	return "$1$" + hex.EncodeToString(h.Sum(nil))
}

func (c *OVHcloudAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL, body string) (*http.Request, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	ts := c.now().Unix()
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Ovh-Application", strings.TrimSpace(secrets.ApplicationKey))
	req.Header.Set("X-Ovh-Consumer", strings.TrimSpace(secrets.ConsumerKey))
	req.Header.Set("X-Ovh-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Ovh-Signature", signOVH(
		strings.TrimSpace(secrets.ApplicationSecret),
		strings.TrimSpace(secrets.ConsumerKey),
		method, fullURL, body, ts))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *OVHcloudAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("ovhcloud: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ovhcloud: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *OVHcloudAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *OVHcloudAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/me"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe, "")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("ovhcloud: connect probe: %w", err)
	}
	return nil
}

func (c *OVHcloudAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type ovhUserDetail struct {
	Login string `json:"login"`
	Email string `json:"email"`
}

func (c *OVHcloudAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *OVHcloudAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	base := c.baseURL(cfg)
	listURL := base + "/me/identity/user"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, listURL, "")
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var logins []string
	if err := json.Unmarshal(body, &logins); err != nil {
		return fmt.Errorf("ovhcloud: decode user list: %w", err)
	}
	identities := make([]*access.Identity, 0, len(logins))
	for _, login := range logins {
		detailURL := base + "/me/identity/user/" + login
		dreq, err := c.newRequest(ctx, secrets, http.MethodGet, detailURL, "")
		if err != nil {
			return err
		}
		dbody, err := c.do(dreq)
		if err != nil {
			// Best-effort: fall back to login-only identity.
			identities = append(identities, &access.Identity{
				ExternalID:  login,
				Type:        access.IdentityTypeUser,
				DisplayName: login,
				Status:      "active",
			})
			continue
		}
		var detail ovhUserDetail
		if err := json.Unmarshal(dbody, &detail); err != nil {
			return fmt.Errorf("ovhcloud: decode user %s: %w", login, err)
		}
		identities = append(identities, &access.Identity{
			ExternalID:  login,
			Type:        access.IdentityTypeUser,
			DisplayName: login,
			Email:       detail.Email,
			Status:      "active",
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker OVHcloud
// Public Cloud SSO federation. When `sso_metadata_url` is blank the
// helper returns (nil, nil) and the caller gracefully downgrades.
func (c *OVHcloudAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *OVHcloudAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":           ProviderName,
		"endpoint":           cfg.Endpoint,
		"auth_type":          "ovh_signature",
		"application_key":    shortToken(secrets.ApplicationKey),
		"consumer_key_short": shortToken(secrets.ConsumerKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*OVHcloudAccessConnector)(nil)
