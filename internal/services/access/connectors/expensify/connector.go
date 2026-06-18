// Package expensify implements the access.AccessConnector contract for the
// Expensify Integration Server policy members API.
package expensify

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

const ProviderName = "expensify"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	PolicyID string `json:"policy_id"`
}

type Secrets struct {
	PartnerUserID     string `json:"partner_user_id"`
	PartnerUserSecret string `json:"partner_user_secret"`
}

type ExpensifyAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *ExpensifyAccessConnector { return &ExpensifyAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("expensify: config is nil")
	}
	var cfg Config
	if v, ok := raw["policy_id"].(string); ok {
		cfg.PolicyID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("expensify: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["partner_user_id"].(string); ok {
		s.PartnerUserID = v
	}
	if v, ok := raw["partner_user_secret"].(string); ok {
		s.PartnerUserSecret = v
	}
	return s, nil
}

func (c Config) validate() error {
	id := strings.TrimSpace(c.PolicyID)
	if id == "" {
		return errors.New("expensify: policy_id is required")
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return errors.New("expensify: policy_id must be alphanumeric")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.PartnerUserID) == "" {
		return errors.New("expensify: partner_user_id is required")
	}
	if strings.TrimSpace(s.PartnerUserSecret) == "" {
		return errors.New("expensify: partner_user_secret is required")
	}
	return nil
}

func (c *ExpensifyAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *ExpensifyAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://integrations.expensify.com"
}

func (c *ExpensifyAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *ExpensifyAccessConnector) buildRequestJSON(cfg Config, secrets Secrets) (string, error) {
	payload := map[string]interface{}{
		"type": "get",
		"credentials": map[string]string{
			"partnerUserID":     strings.TrimSpace(secrets.PartnerUserID),
			"partnerUserSecret": strings.TrimSpace(secrets.PartnerUserSecret),
		},
		"inputSettings": map[string]interface{}{
			"type":     "policyList",
			"policyID": strings.TrimSpace(cfg.PolicyID),
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *ExpensifyAccessConnector) doForm(ctx context.Context, body string) ([]byte, error) {
	form := url.Values{"requestJobDescription": []string{body}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/Integration-Server/ExpensifyIntegrations", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("expensify: post: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("expensify: status %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}

func (c *ExpensifyAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *ExpensifyAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := c.buildRequestJSON(cfg, secrets)
	if err != nil {
		return err
	}
	if _, err := c.doForm(ctx, body); err != nil {
		return fmt.Errorf("expensify: connect probe: %w", err)
	}
	return nil
}

func (c *ExpensifyAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type expEmployee struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Role      string `json:"role"`
	Status    string `json:"submitsTo"`
}

type expPolicy struct {
	ID        string        `json:"id"`
	Employees []expEmployee `json:"employees"`
}

type expResponse struct {
	PolicyList   []expPolicy `json:"policyList"`
	ResponseCode int         `json:"responseCode"`
}

func (c *ExpensifyAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *ExpensifyAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, err := c.buildRequestJSON(cfg, secrets)
	if err != nil {
		return err
	}
	out, err := c.doForm(ctx, body)
	if err != nil {
		return err
	}
	var resp expResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return fmt.Errorf("expensify: decode: %w", err)
	}
	identities := make([]*access.Identity, 0)
	for _, p := range resp.PolicyList {
		for _, e := range p.Employees {
			display := strings.TrimSpace(strings.TrimSpace(e.FirstName) + " " + strings.TrimSpace(e.LastName))
			if display == "" {
				display = e.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  e.Email,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       e.Email,
				Status:      "active",
			})
		}
	}
	return handler(identities, "")
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL if
// configured. Expensify federates SSO via SAML 2.0 with metadata
// hosted by the customer's IdP; when `sso_metadata_url` is blank the
// helper returns nil so callers gracefully downgrade.
func (c *ExpensifyAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *ExpensifyAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":         ProviderName,
		"auth_type":        "partner_credentials",
		"partner_id_short": shortToken(secrets.PartnerUserID),
		"secret_short":     shortToken(secrets.PartnerUserSecret),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*ExpensifyAccessConnector)(nil)
