// Package mixpanel implements the access.AccessConnector contract for the
// Mixpanel organization-members API using a service account.
package mixpanel

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

const ProviderName = "mixpanel"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrganizationID string `json:"organization_id"`
}

type Secrets struct {
	ServiceAccountUser   string `json:"service_account_user"`
	ServiceAccountSecret string `json:"service_account_secret"`
}

type MixpanelAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *MixpanelAccessConnector { return &MixpanelAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("mixpanel: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization_id"].(string); ok {
		cfg.OrganizationID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("mixpanel: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["service_account_user"].(string); ok {
		s.ServiceAccountUser = v
	}
	if v, ok := raw["service_account_secret"].(string); ok {
		s.ServiceAccountSecret = v
	}
	return s, nil
}

func (c Config) validate() error {
	id := strings.TrimSpace(c.OrganizationID)
	if id == "" {
		return errors.New("mixpanel: organization_id is required")
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-') {
			return errors.New("mixpanel: organization_id must be alphanumeric (with hyphens)")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ServiceAccountUser) == "" {
		return errors.New("mixpanel: service_account_user is required")
	}
	if strings.TrimSpace(s.ServiceAccountSecret) == "" {
		return errors.New("mixpanel: service_account_secret is required")
	}
	return nil
}

func (c *MixpanelAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *MixpanelAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://mixpanel.com"
}

func (c *MixpanelAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *MixpanelAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.ServiceAccountUser) + ":" + strings.TrimSpace(secrets.ServiceAccountSecret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *MixpanelAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("mixpanel: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mixpanel: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *MixpanelAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *MixpanelAccessConnector) buildPath(cfg Config) string {
	return "/api/app/organizations/" + url.PathEscape(strings.TrimSpace(cfg.OrganizationID)) + "/members"
}

func (c *MixpanelAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + c.buildPath(cfg)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("mixpanel: connect probe: %w", err)
	}
	return nil
}

func (c *MixpanelAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type mxMember struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type mxListResponse struct {
	Members []mxMember `json:"members"`
}

func (c *MixpanelAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MixpanelAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := c.baseURL() + c.buildPath(cfg)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp mxListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("mixpanel: decode members: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Members))
	for _, m := range resp.Members {
		display := strings.TrimSpace(m.Name)
		if display == "" {
			display = m.Email
		}
		identities = append(identities, &access.Identity{
			ExternalID:  fmt.Sprintf("%d", m.ID),
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.Email,
			Status:      "active",
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Mixpanel SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *MixpanelAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *MixpanelAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":     ProviderName,
		"auth_type":    "service_account_basic",
		"user_short":   shortToken(secrets.ServiceAccountUser),
		"secret_short": shortToken(secrets.ServiceAccountSecret),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*MixpanelAccessConnector)(nil)
