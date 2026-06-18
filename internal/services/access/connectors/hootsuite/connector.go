// Package hootsuite implements the access.AccessConnector contract for the
// Hootsuite /v1/me/organizations/{org_id}/members endpoint with OAuth2 bearer
// auth and cursor pagination.
package hootsuite

import (
	"context"
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
	ProviderName = "hootsuite"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrgID string `json:"org_id"`
}

type Secrets struct {
	Token string `json:"token"`
}

type HootsuiteAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *HootsuiteAccessConnector { return &HootsuiteAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("hootsuite: config is nil")
	}
	var cfg Config
	if v, ok := raw["org_id"].(string); ok {
		cfg.OrgID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("hootsuite: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.OrgID) == "" {
		return errors.New("hootsuite: org_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("hootsuite: token is required")
	}
	return nil
}

func (c *HootsuiteAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *HootsuiteAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://platform.hootsuite.com"
}

func (c *HootsuiteAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *HootsuiteAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *HootsuiteAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("hootsuite: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hootsuite: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *HootsuiteAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *HootsuiteAccessConnector) membersPath(cfg Config) string {
	return "/v1/me/organizations/" + url.PathEscape(strings.TrimSpace(cfg.OrgID)) + "/members"
}

func (c *HootsuiteAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + c.membersPath(cfg) + "?limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("hootsuite: connect probe: %w", err)
	}
	return nil
}

func (c *HootsuiteAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type hsMember struct {
	ID    json.Number `json:"id"`
	Email string      `json:"email"`
	Name  string      `json:"fullName"`
}

type hsListResponse struct {
	Data       []hsMember `json:"data"`
	NextCursor string     `json:"nextCursor"`
}

func (c *HootsuiteAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *HootsuiteAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := strings.TrimSpace(checkpoint)
	base := c.baseURL()
	path := c.membersPath(cfg)
	for {
		q := url.Values{
			"limit": []string{fmt.Sprintf("%d", pageSize)},
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		fullURL := base + path + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp hsListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("hootsuite: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, m := range resp.Data {
			display := strings.TrimSpace(m.Name)
			if display == "" {
				display = m.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      "active",
			})
		}
		if err := handler(identities, resp.NextCursor); err != nil {
			return err
		}
		if resp.NextCursor == "" {
			return nil
		}
		cursor = resp.NextCursor
	}
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// Hootsuite workspace. Hootsuite supports SAML 2.0 SSO via Hootsuite
// Enterprise; the connector forwards operator-supplied URLs verbatim
// via access.SSOMetadataFromConfig so the SSOFederationService can
// register a iam-core SAML broker. Returns (nil, nil) when the
// operator has not supplied a metadata URL so the caller downgrades
// gracefully.
func (c *HootsuiteAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *HootsuiteAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "oauth2_bearer",
		"token_short": shortToken(secrets.Token),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*HootsuiteAccessConnector)(nil)
