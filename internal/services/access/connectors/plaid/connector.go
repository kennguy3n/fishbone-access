// Package plaid implements the access.AccessConnector contract for the
// Plaid /team/list endpoint.
package plaid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ProviderName = "plaid"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Environment string `json:"environment"`
}

type Secrets struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

type PlaidAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *PlaidAccessConnector { return &PlaidAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

var allowedEnvs = map[string]struct{}{
	"sandbox":     {},
	"development": {},
	"production":  {},
}

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("plaid: config is nil")
	}
	var cfg Config
	if v, ok := raw["environment"].(string); ok {
		cfg.Environment = v
	}
	if cfg.Environment == "" {
		cfg.Environment = "production"
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("plaid: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["client_id"].(string); ok {
		s.ClientID = v
	}
	if v, ok := raw["secret"].(string); ok {
		s.Secret = v
	}
	return s, nil
}

func (c Config) validate() error {
	env := strings.ToLower(strings.TrimSpace(c.Environment))
	if _, ok := allowedEnvs[env]; !ok {
		return fmt.Errorf("plaid: environment must be one of sandbox|development|production, got %q", c.Environment)
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("plaid: client_id is required")
	}
	if strings.TrimSpace(s.Secret) == "" {
		return errors.New("plaid: secret is required")
	}
	return nil
}

func (c *PlaidAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *PlaidAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Environment)) {
	case "sandbox":
		return "https://sandbox.plaid.com"
	case "development":
		return "https://development.plaid.com"
	}
	return "https://production.plaid.com"
}

func (c *PlaidAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *PlaidAccessConnector) doJSON(ctx context.Context, fullURL string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("plaid: post: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("plaid: status %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}

func (c *PlaidAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *PlaidAccessConnector) buildBody(secrets Secrets) ([]byte, error) {
	return json.Marshal(map[string]string{
		"client_id": strings.TrimSpace(secrets.ClientID),
		"secret":    strings.TrimSpace(secrets.Secret),
	})
}

func (c *PlaidAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := c.buildBody(secrets)
	if err != nil {
		return err
	}
	if _, err := c.doJSON(ctx, c.baseURL(cfg)+"/team/list", body); err != nil {
		return fmt.Errorf("plaid: connect probe: %w", err)
	}
	return nil
}

func (c *PlaidAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type plaidMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

type plaidListResponse struct {
	Team []plaidMember `json:"team"`
}

func (c *PlaidAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *PlaidAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := c.buildBody(secrets)
	if err != nil {
		return err
	}
	out, err := c.doJSON(ctx, c.baseURL(cfg)+"/team/list", body)
	if err != nil {
		return err
	}
	var resp plaidListResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return fmt.Errorf("plaid: decode team: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Team))
	for _, m := range resp.Team {
		display := strings.TrimSpace(m.Name)
		if display == "" {
			display = m.Email
		}
		extID := m.ID
		if extID == "" {
			extID = m.Email
		}
		identities = append(identities, &access.Identity{
			ExternalID:  extID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.Email,
			Status:      "active",
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Plaid SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *PlaidAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *PlaidAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":        ProviderName,
		"auth_type":       "client_id_secret",
		"client_id_short": shortToken(secrets.ClientID),
		"secret_short":    shortToken(secrets.Secret),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*PlaidAccessConnector)(nil)
