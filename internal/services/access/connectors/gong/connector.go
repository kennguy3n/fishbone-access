// Package gong implements the access.AccessConnector contract for the
// Gong /v2/users API.
package gong

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

const ProviderName = "gong"

var ErrNotImplemented = fmt.Errorf("gong: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type GongAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *GongAccessConnector { return &GongAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("gong: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("gong: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_key"].(string); ok {
		s.AccessKey = v
	}
	if v, ok := raw["secret_key"].(string); ok {
		s.SecretKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessKey) == "" {
		return errors.New("gong: access_key is required")
	}
	if strings.TrimSpace(s.SecretKey) == "" {
		return errors.New("gong: secret_key is required")
	}
	return nil
}

func (c *GongAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GongAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.gong.io"
}

func (c *GongAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *GongAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.AccessKey) + ":" + strings.TrimSpace(secrets.SecretKey)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *GongAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gong: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gong: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *GongAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GongAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/v2/users"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("gong: connect probe: %w", err)
	}
	return nil
}

func (c *GongAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type gongUser struct {
	ID        string `json:"id"`
	EmailAddr string `json:"emailAddress"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Title     string `json:"title"`
	Active    bool   `json:"active"`
}

type gongListResponse struct {
	Users   []gongUser `json:"users"`
	Records struct {
		Cursor string `json:"cursor"`
	} `json:"records"`
}

func (c *GongAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GongAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	base := c.baseURL()
	for {
		path := base + "/v2/users"
		if cursor != "" {
			path += "?cursor=" + url.QueryEscape(cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp gongListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("gong: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := strings.TrimSpace(u.FirstName + " " + u.LastName)
			if display == "" {
				display = u.EmailAddr
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.EmailAddr,
				Status:      status,
				RawData:     map[string]interface{}{"title": u.Title},
			})
		}
		next := resp.Records.Cursor
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the Gong
// workspace. Gong Enterprise supports SAML 2.0 SSO with metadata hosted
// by the customer's IdP; the connector forwards operator-supplied URLs
// verbatim via access.SSOMetadataFromConfig so the SSOFederationService
// can register a iam-core SAML broker. Returns (nil, nil) when the
// operator has not supplied a metadata URL so the caller downgrades
// gracefully.
func (c *GongAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *GongAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":     ProviderName,
		"auth_type":    "basic",
		"key_short":    shortToken(secrets.AccessKey),
		"secret_short": shortToken(secrets.SecretKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*GongAccessConnector)(nil)
