// Package klaviyo implements the access.AccessConnector contract for the
// Klaviyo /api/accounts/ API.
package klaviyo

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
	ProviderName = "klaviyo"
	apiRevision  = "2024-10-15"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type KlaviyoAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *KlaviyoAccessConnector { return &KlaviyoAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("klaviyo: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("klaviyo: secrets is nil")
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
		return errors.New("klaviyo: api_key is required")
	}
	return nil
}

func (c *KlaviyoAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *KlaviyoAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://a.klaviyo.com"
}

func (c *KlaviyoAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *KlaviyoAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "Klaviyo-API-Key "+strings.TrimSpace(secrets.APIKey))
	req.Header.Set("revision", apiRevision)
	return req, nil
}

func (c *KlaviyoAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("klaviyo: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("klaviyo: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *KlaviyoAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *KlaviyoAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/api/accounts/"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("klaviyo: connect probe: %w", err)
	}
	return nil
}

func (c *KlaviyoAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type klaviyoAccount struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		ContactInformation struct {
			DefaultSenderName  string `json:"default_sender_name"`
			DefaultSenderEmail string `json:"default_sender_email"`
			OrganizationName   string `json:"organization_name"`
		} `json:"contact_information"`
		IndustryStatus    string `json:"industry"`
		PreferredCurrency string `json:"preferred_currency"`
		PublicAPIKey      string `json:"public_api_key"`
		Locale            string `json:"locale"`
	} `json:"attributes"`
}

type klaviyoLinks struct {
	Next string `json:"next"`
}

type klaviyoListResponse struct {
	Data  []klaviyoAccount `json:"data"`
	Links klaviyoLinks     `json:"links"`
}

func (c *KlaviyoAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

// extractCursor parses a `page[cursor]` value out of an absolute next URL.
func extractCursor(nextURL string) string {
	if nextURL == "" {
		return ""
	}
	u, err := url.Parse(nextURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("page[cursor]")
}

func (c *KlaviyoAccessConnector) SyncIdentities(
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
		path := base + "/api/accounts/"
		if cursor != "" {
			path += "?" + url.Values{"page[cursor]": []string{cursor}}.Encode()
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp klaviyoListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("klaviyo: decode accounts: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, a := range resp.Data {
			display := a.Attributes.ContactInformation.OrganizationName
			if display == "" {
				display = a.Attributes.ContactInformation.DefaultSenderName
			}
			if display == "" {
				display = a.Attributes.ContactInformation.DefaultSenderEmail
			}
			if display == "" {
				display = a.ID
			}
			identities = append(identities, &access.Identity{
				ExternalID:  a.ID,
				Type:        access.IdentityTypeServiceAccount,
				DisplayName: display,
				Email:       a.Attributes.ContactInformation.DefaultSenderEmail,
				Status:      "active",
				RawData: map[string]interface{}{
					"industry":           a.Attributes.IndustryStatus,
					"preferred_currency": a.Attributes.PreferredCurrency,
					"public_api_key":     a.Attributes.PublicAPIKey,
					"locale":             a.Attributes.Locale,
				},
			})
		}
		next := extractCursor(resp.Links.Next)
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Klaviyo SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *KlaviyoAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *KlaviyoAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "klaviyo_api_key",
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

var _ access.AccessConnector = (*KlaviyoAccessConnector)(nil)
