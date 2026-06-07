// Package wrike implements the access.AccessConnector contract for the
// Wrike /api/v4/contacts API.
package wrike

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
	ProviderName = "wrike"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("wrike: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// Host overrides the API host (e.g. "www.wrike.com" or "app-us2.wrike.com").
	Host string `json:"host"`
}

type Secrets struct {
	Token string `json:"token"`
}

type WrikeAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *WrikeAccessConnector { return &WrikeAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("wrike: config is nil")
	}
	var cfg Config
	if v, ok := raw["host"].(string); ok {
		cfg.Host = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("wrike: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	host := strings.TrimSpace(c.Host)
	if host == "" {
		return nil
	}
	if !isHost(host) {
		return errors.New("wrike: host must contain only DNS label characters and dots")
	}
	return nil
}

func isHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("wrike: token is required")
	}
	return nil
}

func (c *WrikeAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *WrikeAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "www.wrike.com"
	}
	return "https://" + host
}

func (c *WrikeAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *WrikeAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *WrikeAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("wrike: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wrike: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *WrikeAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *WrikeAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/api/v4/contacts?pageSize=1", c.baseURL(cfg))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("wrike: connect probe: %w", err)
	}
	return nil
}

func (c *WrikeAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type wrikeContact struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Type      string `json:"type"`
	Profiles  []struct {
		Email string `json:"email"`
	} `json:"profiles"`
	Deleted bool `json:"deleted"`
}

type wrikeListResponse struct {
	Data          []wrikeContact `json:"data"`
	NextPageToken string         `json:"nextPageToken"`
}

func (c *WrikeAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *WrikeAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token := checkpoint
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/api/v4/contacts?pageSize=%d", base, pageSize)
		if token != "" {
			path += "&nextPageToken=" + url.QueryEscape(token)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp wrikeListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("wrike: decode contacts: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, ct := range resp.Data {
			email := ""
			if len(ct.Profiles) > 0 {
				email = ct.Profiles[0].Email
			}
			display := strings.TrimSpace(ct.FirstName + " " + ct.LastName)
			if display == "" {
				display = email
			}
			idType := access.IdentityTypeUser
			if strings.EqualFold(ct.Type, "Group") {
				idType = access.IdentityTypeGroup
			}
			status := "active"
			if ct.Deleted {
				status = "deleted"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  ct.ID,
				Type:        idType,
				DisplayName: display,
				Email:       email,
				Status:      status,
			})
		}
		next := resp.NextPageToken
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		token = next
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Wrike SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *WrikeAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *WrikeAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "bearer",
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

var _ access.AccessConnector = (*WrikeAccessConnector)(nil)
