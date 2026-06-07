// Package make implements the access.AccessConnector contract for the
// Make (Integromat) /api/v2/users endpoint with bearer auth and the unusual
// pg[offset]/pg[limit] pagination encoding.
package make

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "make"
	pageSize     = 100

	// defaultRegion is the Make zone used when neither base_url nor region is
	// configured. eu1 was the connector's original hardcoded endpoint, so it
	// remains the default for backwards compatibility.
	defaultRegion = "eu1"
)

var ErrNotImplemented = fmt.Errorf("make: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// BaseURL optionally overrides the full API base (scheme + host), for
	// white-label or self-hosted Make deployments. When set it takes
	// precedence over Region.
	BaseURL string `json:"base_url"`
	// Region selects the Make zone subdomain (e.g. "eu1", "eu2", "us1",
	// "us2"). When BaseURL is empty the base resolves to
	// https://{Region}.make.com. Defaults to defaultRegion when both are
	// empty.
	Region string `json:"region"`
}

type Secrets struct {
	Token string `json:"token"`
}

type MakeAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *MakeAccessConnector { return &MakeAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("make: config is nil")
	}
	var cfg Config
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = strings.TrimSpace(v)
	}
	if v, ok := raw["region"].(string); ok {
		cfg.Region = strings.TrimSpace(v)
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("make: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	// A region is just a zone subdomain (e.g. "eu1"). Restrict it to an
	// alphanumeric+hyphen allowlist so it can only ever be interpolated as a
	// single DNS label in https://{region}.make.com — this rejects both full
	// URLs (scheme/slash/dot) placed in the wrong field and any other
	// injection (whitespace, ";", etc.) that would build a malformed host.
	// Operators needing a non-zone host should use base_url instead.
	for _, r := range c.Region {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-') {
			return errors.New(`make: region must be a zone subdomain like "eu1" (alphanumeric with hyphens; use base_url for a full URL)`)
		}
	}
	// base_url is the credential-bearing endpoint, so when set it must be an
	// absolute https URL. Rejecting plaintext http (and loopback exceptions for
	// local dev/testing) prevents a misconfiguration from sending the bearer
	// token in cleartext to a self-hosted/white-label host.
	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil || u.Host == "" {
			return errors.New("make: base_url must be an absolute URL like https://make.example.com")
		}
		if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
			return errors.New("make: base_url must use https (http is only allowed for loopback hosts)")
		}
	}
	return nil
}

// isLoopbackHost reports whether host is a loopback name/address, for which
// plaintext http base_url is tolerated (local development and tests).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("make: token is required")
	}
	return nil
}

func (c *MakeAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *MakeAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if cfg.BaseURL != "" {
		return strings.TrimRight(cfg.BaseURL, "/")
	}
	region := cfg.Region
	if region == "" {
		region = defaultRegion
	}
	return "https://" + region + ".make.com"
}

func (c *MakeAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *MakeAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	// Make's documented header form is "Authorization: Token <api-key>".
	req.Header.Set("Authorization", "Token "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *MakeAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("make: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("make: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *MakeAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *MakeAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/v2/users?pg%5Boffset%5D=0&pg%5Blimit%5D=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("make: connect probe: %w", err)
	}
	return nil
}

func (c *MakeAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type makeUser struct {
	ID    json.Number `json:"id"`
	Email string      `json:"email"`
	Name  string      `json:"name"`
}

type makeListResponse struct {
	Users []makeUser `json:"users"`
}

func (c *MakeAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MakeAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		q := url.Values{
			"pg[offset]": []string{fmt.Sprintf("%d", offset)},
			"pg[limit]":  []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := base + "/api/v2/users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp makeListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("make: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if len(resp.Users) == pageSize {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
}

func (c *MakeAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *MakeAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "token",
		"token_short": shortToken(secrets.Token),
	}, nil
}

// shortToken returns a redacted, human-identifiable hint for a credential
// without ever exposing the secret itself. GetCredentialsMetadata is documented
// as returning metadata without decrypting the secret, and its result is
// surfaced in admin UIs and logs, so the raw value must never appear. It only
// reveals a 4-char prefix and suffix when the token is long enough (>=12) to
// keep at least 4 characters hidden; shorter tokens are fully masked.
func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if len(t) < 12 {
		return "***"
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*MakeAccessConnector)(nil)
