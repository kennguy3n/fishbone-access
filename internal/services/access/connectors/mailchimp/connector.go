// Package mailchimp implements the access.AccessConnector contract for the
// Mailchimp /3.0/lists/{list_id}/members API.
package mailchimp

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

const (
	ProviderName = "mailchimp"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("mailchimp: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	ListID string `json:"list_id"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type MailchimpAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *MailchimpAccessConnector { return &MailchimpAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("mailchimp: config is nil")
	}
	var cfg Config
	if v, ok := raw["list_id"].(string); ok {
		cfg.ListID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("mailchimp: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	id := strings.TrimSpace(c.ListID)
	if id == "" {
		return errors.New("mailchimp: list_id is required")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		default:
			return errors.New("mailchimp: list_id must be alphanumeric")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	key := strings.TrimSpace(s.APIKey)
	if key == "" {
		return errors.New("mailchimp: api_key is required")
	}
	if dc := datacenter(key); dc == "" {
		return errors.New("mailchimp: api_key must contain a datacenter suffix (e.g. abc-us12)")
	} else if !isDNSLabel(dc) {
		return errors.New("mailchimp: api_key datacenter suffix must be a single DNS label")
	}
	return nil
}

func datacenter(apiKey string) string {
	idx := strings.LastIndex(apiKey, "-")
	if idx < 0 || idx == len(apiKey)-1 {
		return ""
	}
	return apiKey[idx+1:]
}

func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

func (c *MailchimpAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *MailchimpAccessConnector) baseURL(s Secrets) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	dc := datacenter(strings.TrimSpace(s.APIKey))
	return "https://" + dc + ".api.mailchimp.com"
}

func (c *MailchimpAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *MailchimpAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := "anystring:" + strings.TrimSpace(secrets.APIKey)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *MailchimpAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("mailchimp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mailchimp: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *MailchimpAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *MailchimpAccessConnector) membersURL(cfg Config, s Secrets) string {
	return fmt.Sprintf("%s/3.0/lists/%s/members", c.baseURL(s), url.PathEscape(strings.TrimSpace(cfg.ListID)))
}

func (c *MailchimpAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.membersURL(cfg, secrets) + "?offset=0&count=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("mailchimp: connect probe: %w", err)
	}
	return nil
}

func (c *MailchimpAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type mailchimpMember struct {
	ID          string `json:"id"`
	Email       string `json:"email_address"`
	UniqueEmail string `json:"unique_email_id"`
	FullName    string `json:"full_name"`
	Status      string `json:"status"`
}

type mailchimpListResponse struct {
	Members    []mailchimpMember `json:"members"`
	TotalItems int               `json:"total_items"`
	ListID     string            `json:"list_id"`
}

func (c *MailchimpAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MailchimpAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	memURL := c.membersURL(cfg, secrets)
	for {
		path := fmt.Sprintf("%s?offset=%d&count=%d", memURL, offset, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp mailchimpListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("mailchimp: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Members))
		for _, m := range resp.Members {
			display := m.FullName
			if display == "" {
				display = m.Email
			}
			status := strings.ToLower(strings.TrimSpace(m.Status))
			if status == "" {
				status = "subscribed"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      status,
			})
		}
		next := ""
		fetched := offset + len(resp.Members)
		if len(resp.Members) == pageSize && fetched < resp.TotalItems {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Mailchimp SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *MailchimpAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *MailchimpAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":   ProviderName,
		"auth_type":  "basic",
		"key_short":  shortToken(secrets.APIKey),
		"datacenter": datacenter(strings.TrimSpace(secrets.APIKey)),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*MailchimpAccessConnector)(nil)
