// Package insightly implements the access.AccessConnector contract for the
// Insightly /v3.1/Users API.
package insightly

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "insightly"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("insightly: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Pod string `json:"pod"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type InsightlyAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *InsightlyAccessConnector { return &InsightlyAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("insightly: config is nil")
	}
	var cfg Config
	if v, ok := raw["pod"].(string); ok {
		cfg.Pod = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("insightly: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if c.Pod == "" {
		return nil
	}
	if !isDNSLabel(c.Pod) {
		return errors.New("insightly: pod must be a single DNS label (e.g. na1, eu1)")
	}
	return nil
}

func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("insightly: api_key is required")
	}
	return nil
}

func (c *InsightlyAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *InsightlyAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	pod := strings.TrimSpace(cfg.Pod)
	if pod == "" {
		pod = "na1"
	}
	return "https://api." + pod + ".insightly.com"
}

func (c *InsightlyAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *InsightlyAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.APIKey) + ":"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *InsightlyAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("insightly: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("insightly: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *InsightlyAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *InsightlyAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	q := url.Values{"skip": []string{"0"}, "top": []string{"1"}}
	probe := c.baseURL(cfg) + "/v3.1/Users?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("insightly: connect probe: %w", err)
	}
	return nil
}

func (c *InsightlyAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type insightlyUser struct {
	UserID       int64  `json:"USER_ID"`
	FirstName    string `json:"FIRST_NAME"`
	LastName     string `json:"LAST_NAME"`
	EmailAddress string `json:"EMAIL_ADDRESS"`
	Active       bool   `json:"ACTIVE"`
}

func (c *InsightlyAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *InsightlyAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	skip := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &skip)
		if skip < 0 {
			skip = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		q := url.Values{
			"skip": []string{fmt.Sprintf("%d", skip)},
			"top":  []string{fmt.Sprintf("%d", pageSize)},
		}
		path := base + "/v3.1/Users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var users []insightlyUser
		if err := json.Unmarshal(body, &users); err != nil {
			return fmt.Errorf("insightly: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(users))
		for _, u := range users {
			display := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
			if display == "" {
				display = u.EmailAddress
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", u.UserID),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.EmailAddress,
				Status:      status,
			})
		}
		next := ""
		if len(users) == pageSize {
			next = fmt.Sprintf("%d", skip+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		skip += pageSize
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Insightly SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *InsightlyAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *InsightlyAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "basic_apikey",
		"key_short": shortToken(secrets.APIKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*InsightlyAccessConnector)(nil)
