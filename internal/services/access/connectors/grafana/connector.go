// Package grafana implements the access.AccessConnector contract for the
// Grafana /api/org/users API.
//
// Grafana's /api/org/users endpoint is single-page and returns the entire
// list of users for the calling org's API key in one request. Auth is
// either a bearer service-account token or HTTP Basic for legacy admin
// credentials.
package grafana

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ProviderName = "grafana"

var ErrNotImplemented = fmt.Errorf("grafana: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	BaseURL string `json:"base_url"`
}

type Secrets struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type GrafanaAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *GrafanaAccessConnector { return &GrafanaAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("grafana: config is nil")
	}
	var cfg Config
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("grafana: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	if v, ok := raw["username"].(string); ok {
		s.Username = v
	}
	if v, ok := raw["password"].(string); ok {
		s.Password = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("grafana: base_url is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) != "" {
		return nil
	}
	if strings.TrimSpace(s.Username) != "" && strings.TrimSpace(s.Password) != "" {
		return nil
	}
	return errors.New("grafana: token or username+password required")
}

func (c *GrafanaAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GrafanaAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
}

func (c *GrafanaAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *GrafanaAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if t := strings.TrimSpace(secrets.Token); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	} else {
		creds := strings.TrimSpace(secrets.Username) + ":" + strings.TrimSpace(secrets.Password)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	return req, nil
}

func (c *GrafanaAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("grafana: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("grafana: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *GrafanaAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GrafanaAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/org/users"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("grafana: connect probe: %w", err)
	}
	return nil
}

func (c *GrafanaAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type grafanaUser struct {
	UserID     int64  `json:"userId"`
	Email      string `json:"email"`
	Login      string `json:"login"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	IsDisabled bool   `json:"isDisabled"`
}

func (c *GrafanaAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GrafanaAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := c.baseURL(cfg) + "/api/org/users"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var users []grafanaUser
	if err := json.Unmarshal(body, &users); err != nil {
		return fmt.Errorf("grafana: decode users: %w", err)
	}
	identities := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		display := u.Name
		if display == "" {
			display = u.Login
		}
		if display == "" {
			display = u.Email
		}
		status := "active"
		if u.IsDisabled {
			status = "disabled"
		}
		identities = append(identities, &access.Identity{
			ExternalID:  fmt.Sprintf("%d", u.UserID),
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       u.Email,
			Status:      status,
			RawData:     map[string]interface{}{"role": u.Role},
		})
	}
	return handler(identities, "")
}

// ProvisionAccess, RevokeAccess, ListEntitlements: see advanced.go.

func (c *GrafanaAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *GrafanaAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	md := map[string]interface{}{"provider": ProviderName}
	if strings.TrimSpace(secrets.Token) != "" {
		md["auth_type"] = "bearer"
		md["token_short"] = shortToken(secrets.Token)
	} else {
		md["auth_type"] = "basic"
		md["username_short"] = shortToken(secrets.Username)
		md["password_short"] = shortToken(secrets.Password)
	}
	return md, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*GrafanaAccessConnector)(nil)
