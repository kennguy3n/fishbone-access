// Package hibob implements the access.AccessConnector contract for the
// Hibob people API.
package hibob

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

const ProviderName = "hibob"

var ErrNotImplemented = fmt.Errorf("hibob: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type HibobAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *HibobAccessConnector { return &HibobAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("hibob: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("hibob: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("hibob: api_token is required")
	}
	return nil
}

func (c *HibobAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *HibobAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.hibob.com"
}

func (c *HibobAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *HibobAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *HibobAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("hibob: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hibob: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *HibobAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *HibobAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/v1/people?showInactive=false"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("hibob: connect probe: %w", err)
	}
	return nil
}

func (c *HibobAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type hibobEmployee struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	FirstName   string `json:"firstName"`
	Surname     string `json:"surname"`
	Email       string `json:"email"`
	Active      bool   `json:"active"`
}

type hibobResponse struct {
	Employees []hibobEmployee `json:"employees"`
}

func (c *HibobAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *HibobAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := c.baseURL() + "/v1/people?showInactive=true"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp hibobResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("hibob: decode people: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Employees))
	for _, e := range resp.Employees {
		display := e.DisplayName
		if display == "" {
			display = strings.TrimSpace(e.FirstName + " " + e.Surname)
		}
		if display == "" {
			display = e.Email
		}
		status := "active"
		if !e.Active {
			status = "inactive"
		}
		identities = append(identities, &access.Identity{
			ExternalID:  e.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       e.Email,
			Status:      status,
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// HiBob workspace. HiBob supports SAML 2.0 SSO via the HiBob admin
// console; the connector forwards the operator-supplied URLs
// verbatim via access.SSOMetadataFromConfig so the
// SSOFederationService can register a iam-core SAML broker. Returns
// (nil, nil) when the operator has not supplied a metadata URL so
// the caller gracefully downgrades.
func (c *HibobAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *HibobAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "service_user_token",
		"token_short": shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return strings.Repeat("*", len(t))
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*HibobAccessConnector)(nil)
