// Package crisp implements the access.AccessConnector contract for the
// Crisp /v1/website/{website_id}/operators/list API.
package crisp

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

const ProviderName = "crisp"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	WebsiteID string `json:"website_id"`
}

type Secrets struct {
	Identifier string `json:"identifier"`
	Key        string `json:"key"`
}

type CrispAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *CrispAccessConnector { return &CrispAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("crisp: config is nil")
	}
	var cfg Config
	if v, ok := raw["website_id"].(string); ok {
		cfg.WebsiteID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("crisp: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["identifier"].(string); ok {
		s.Identifier = v
	}
	if v, ok := raw["key"].(string); ok {
		s.Key = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.WebsiteID) == "" {
		return errors.New("crisp: website_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Identifier) == "" {
		return errors.New("crisp: identifier is required")
	}
	if strings.TrimSpace(s.Key) == "" {
		return errors.New("crisp: key is required")
	}
	return nil
}

func (c *CrispAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *CrispAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.crisp.chat"
}

func (c *CrispAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *CrispAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Crisp-Tier", "plugin")
	creds := strings.TrimSpace(secrets.Identifier) + ":" + strings.TrimSpace(secrets.Key)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *CrispAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("crisp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("crisp: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *CrispAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *CrispAccessConnector) operatorsURL(cfg Config) string {
	return fmt.Sprintf("%s/v1/website/%s/operators/list", c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.WebsiteID)))
}

func (c *CrispAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.operatorsURL(cfg))
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("crisp: connect probe: %w", err)
	}
	return nil
}

func (c *CrispAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type crispOperator struct {
	Type    string `json:"type"`
	Details struct {
		UserID    string `json:"user_id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Role      string `json:"role"`
	} `json:"details"`
}

type crispListResponse struct {
	Error  bool            `json:"error"`
	Reason string          `json:"reason"`
	Data   []crispOperator `json:"data"`
}

func (c *CrispAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *CrispAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.operatorsURL(cfg))
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp crispListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("crisp: decode operators: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Data))
	for _, op := range resp.Data {
		display := strings.TrimSpace(op.Details.FirstName + " " + op.Details.LastName)
		if display == "" {
			display = op.Details.Email
		}
		identities = append(identities, &access.Identity{
			ExternalID:  op.Details.UserID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       op.Details.Email,
			Status:      "active",
			RawData:     map[string]interface{}{"role": op.Details.Role},
		})
	}
	return handler(identities, "")
}

func (c *CrispAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *CrispAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":         ProviderName,
		"auth_type":        "basic",
		"identifier_short": shortToken(secrets.Identifier),
		"key_short":        shortToken(secrets.Key),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*CrispAccessConnector)(nil)
