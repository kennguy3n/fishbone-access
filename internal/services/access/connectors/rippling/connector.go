// Package rippling implements the access.AccessConnector contract for the
// Rippling Platform employees API.
package rippling

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
	ProviderName = "rippling"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("rippling: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// SAMLMetadataURL points at the Rippling-issued SAML 2.0 metadata
	// document for the customer (typically rendered in the Rippling
	// admin console under SSO settings). When set the connector
	// advertises Rippling SAML metadata via GetSSOMetadata.
	SAMLMetadataURL string `json:"saml_metadata_url,omitempty"`
	// SAMLEntityID is the IdP entity ID configured for the customer.
	// Optional — when empty the metadata URL is used as the entity ID.
	SAMLEntityID string `json:"saml_entity_id,omitempty"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type RipplingAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *RipplingAccessConnector { return &RipplingAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("rippling: config is nil")
	}
	var cfg Config
	if v, ok := raw["saml_metadata_url"].(string); ok {
		cfg.SAMLMetadataURL = v
	}
	if v, ok := raw["saml_entity_id"].(string); ok {
		cfg.SAMLEntityID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("rippling: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("rippling: api_key is required")
	}
	return nil
}

func (c *RipplingAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *RipplingAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.rippling.com"
}

func (c *RipplingAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *RipplingAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *RipplingAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("rippling: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rippling: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *RipplingAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *RipplingAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/platform/api/me"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("rippling: connect probe: %w", err)
	}
	return nil
}

func (c *RipplingAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type ripplingEmployee struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	WorkEmail string `json:"workEmail"`
	Status    string `json:"status"`
}

type ripplingResponse struct {
	Results    []ripplingEmployee `json:"results"`
	Next       string             `json:"next"`
	NextCursor string             `json:"nextCursor"`
}

func (c *RipplingAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *RipplingAccessConnector) SyncIdentities(
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
		path := fmt.Sprintf("%s/platform/api/employees?limit=%d", base, pageSize)
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp ripplingResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("rippling: decode employees: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Results))
		for _, e := range resp.Results {
			display := strings.TrimSpace(e.FirstName + " " + e.LastName)
			if display == "" {
				display = e.WorkEmail
			}
			status := "active"
			if e.Status != "" && !strings.EqualFold(e.Status, "active") {
				status = strings.ToLower(e.Status)
			}
			identities = append(identities, &access.Identity{
				ExternalID:  e.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       e.WorkEmail,
				Status:      status,
			})
		}
		next := resp.NextCursor
		if next == "" {
			next = resp.Next
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// GetSSOMetadata advertises Rippling SAML metadata when the connector
// is configured with a saml_metadata_url. Rippling's SAML IdP is
// rendered per-customer; the operator provides the metadata URL from
// the Rippling admin console. Returns (nil, nil) when the metadata
// URL is not set so callers treat the connector as SSO-unsupported
// (ErrSSOFederationUnsupported).
func (c *RipplingAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	metaURL := strings.TrimSpace(cfg.SAMLMetadataURL)
	if metaURL == "" {
		return nil, nil
	}
	entity := strings.TrimSpace(cfg.SAMLEntityID)
	if entity == "" {
		entity = metaURL
	}
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: metaURL,
		EntityID:    entity,
	}, nil
}

func (c *RipplingAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "api_key",
		"key_short": shortToken(secrets.APIKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*RipplingAccessConnector)(nil)
