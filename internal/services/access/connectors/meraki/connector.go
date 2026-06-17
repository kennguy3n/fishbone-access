// Package meraki implements the access.AccessConnector contract for the
// Cisco Meraki /api/v1/admins API.
package meraki

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

const ProviderName = "meraki"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config carries the connector's non-secret settings. organization_id is
// required: every Meraki Dashboard endpoint this connector calls
// (getOrganizationAdmins, action batches, admin provision/revoke) is scoped
// under /organizations/{organization_id}, so the value is decoded into the
// typed Config and enforced by validate() — making Validate() fail closed at
// connector-test time rather than deferring the error to the first sync.
type Config struct {
	OrganizationID string `json:"organization_id"`
}

type Secrets struct {
	Token string `json:"token"`
}

type MerakiAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *MerakiAccessConnector { return &MerakiAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("meraki: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization_id"].(string); ok {
		cfg.OrganizationID = strings.TrimSpace(v)
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("meraki: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if c.OrganizationID == "" {
		return errors.New("meraki: organization_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("meraki: token is required")
	}
	return nil
}

func (c *MerakiAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *MerakiAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.meraki.com"
}

func (c *MerakiAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *MerakiAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Cisco-Meraki-API-Key", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *MerakiAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("meraki: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("meraki: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *MerakiAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *MerakiAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.adminsURL(cfg.OrganizationID))
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("meraki: connect probe: %w", err)
	}
	return nil
}

func (c *MerakiAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

// merakiUser mirrors the per-admin payload returned by the Meraki Dashboard
// `getOrganizationAdmins` endpoint. The endpoint only returns currently
// provisioned admins and exposes no per-admin enable/disable flag, so we do
// not derive identity status from any boolean field on this struct.
type merakiUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (c *MerakiAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MerakiAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.adminsURL(cfg.OrganizationID))
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	// getOrganizationAdmins returns a bare JSON array of admins and is not a
	// paginated endpoint, so a single request yields the complete set.
	var admins []merakiUser
	if err := json.Unmarshal(body, &admins); err != nil {
		return fmt.Errorf("meraki: decode admins: %w", err)
	}
	identities := make([]*access.Identity, 0, len(admins))
	for _, u := range admins {
		display := strings.TrimSpace(u.Name)
		if display == "" {
			display = u.Email
		}
		identities = append(identities, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       u.Email,
			Status:      "active",
		})
	}
	return handler(identities, "")
}

func (c *MerakiAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *MerakiAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_key",
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

var _ access.AccessConnector = (*MerakiAccessConnector)(nil)
