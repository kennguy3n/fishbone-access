// Package xero implements the access.AccessConnector contract for the
// Xero Users API.
package xero

import (
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

const (
	ProviderName = "xero"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TenantID string `json:"tenant_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type XeroAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *XeroAccessConnector { return &XeroAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("xero: config is nil")
	}
	var cfg Config
	if v, ok := raw["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("xero: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.TenantID) == "" {
		return errors.New("xero: tenant_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("xero: access_token is required")
	}
	return nil
}

func (c *XeroAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *XeroAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.xero.com"
}

func (c *XeroAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *XeroAccessConnector) newRequest(ctx context.Context, cfg Config, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	req.Header.Set("Xero-Tenant-Id", strings.TrimSpace(cfg.TenantID))
	return req, nil
}

func (c *XeroAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("xero: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("xero: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *XeroAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *XeroAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/api.xro/2.0/Organisation"
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("xero: connect probe: %w", err)
	}
	return nil
}

func (c *XeroAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type xeroUser struct {
	UserID           string `json:"UserID"`
	EmailAddress     string `json:"EmailAddress"`
	FirstName        string `json:"FirstName"`
	LastName         string `json:"LastName"`
	IsSubscriber     bool   `json:"IsSubscriber"`
	OrganisationRole string `json:"OrganisationRole"`
}

type xeroUsersResponse struct {
	Users []xeroUser `json:"Users"`
}

func (c *XeroAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *XeroAccessConnector) SyncIdentities(
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
	base := c.baseURL()
	for {
		path := fmt.Sprintf("%s/api.xro/2.0/Users?page=%d", base, page)
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp xeroUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("xero: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := strings.TrimSpace(u.FirstName + " " + u.LastName)
			if display == "" {
				display = u.EmailAddress
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.UserID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.EmailAddress,
				Status:      "active",
				RawData:     map[string]interface{}{"role": u.OrganisationRole, "is_subscriber": u.IsSubscriber},
			})
		}
		next := ""
		if len(resp.Users) >= pageSize {
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
// `sso_entity_id` into the shared SAML envelope used to broker Xero SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *XeroAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *XeroAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"tenant_id":   cfg.TenantID,
		"auth_type":   "oauth2",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*XeroAccessConnector)(nil)
