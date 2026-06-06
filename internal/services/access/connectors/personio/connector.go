// Package personio implements the access.AccessConnector contract for the
// Personio company employees API.
package personio

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
	ProviderName = "personio"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("personio: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type PersonioAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *PersonioAccessConnector { return &PersonioAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("personio: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("personio: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["client_id"].(string); ok {
		s.ClientID = v
	}
	if v, ok := raw["client_secret"].(string); ok {
		s.ClientSecret = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("personio: client_id is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return errors.New("personio: client_secret is required")
	}
	return nil
}

func (c *PersonioAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *PersonioAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.personio.de"
}

func (c *PersonioAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *PersonioAccessConnector) authToken(ctx context.Context, secrets Secrets) (string, error) {
	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(secrets.ClientID))
	form.Set("client_secret", strings.TrimSpace(secrets.ClientSecret))
	encoded := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/v1/auth", strings.NewReader(encoded))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(encoded))
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("personio: auth: network error")
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("personio: auth: status %d", resp.StatusCode)
	}
	var parsed struct {
		Success bool `json:"success"`
		Data    struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("personio: decode auth: %w", err)
	}
	if parsed.Data.Token == "" {
		return "", errors.New("personio: auth returned empty token")
	}
	return parsed.Data.Token, nil
}

func (c *PersonioAccessConnector) newRequest(ctx context.Context, token, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

func (c *PersonioAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("personio: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("personio: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *PersonioAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *PersonioAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.authToken(ctx, secrets); err != nil {
		return fmt.Errorf("personio: connect probe: %w", err)
	}
	return nil
}

func (c *PersonioAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type personioAttributeWrapper struct {
	Value interface{} `json:"value"`
}

type personioEmployee struct {
	Type       string                              `json:"type"`
	Attributes map[string]personioAttributeWrapper `json:"attributes"`
}

type personioListResponse struct {
	Success  bool               `json:"success"`
	Data     []personioEmployee `json:"data"`
	Metadata struct {
		TotalElements int `json:"total_elements"`
		CurrentPage   int `json:"current_page"`
		TotalPages    int `json:"total_pages"`
	} `json:"metadata"`
}

func attrString(emp personioEmployee, key string) string {
	wrapped, ok := emp.Attributes[key]
	if !ok {
		return ""
	}
	if v, ok := wrapped.Value.(string); ok {
		return v
	}
	return ""
}

func attrInt(emp personioEmployee, key string) int {
	wrapped, ok := emp.Attributes[key]
	if !ok {
		return 0
	}
	switch v := wrapped.Value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func (c *PersonioAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *PersonioAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.authToken(ctx, secrets)
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
	base := c.baseURL()
	for {
		path := fmt.Sprintf("%s/v1/company/employees?offset=%d&limit=%d", base, offset, pageSize)
		req, err := c.newRequest(ctx, token, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp personioListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("personio: decode employees: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, e := range resp.Data {
			id := fmt.Sprintf("%d", attrInt(e, "id"))
			email := attrString(e, "email")
			first := attrString(e, "first_name")
			last := attrString(e, "last_name")
			display := strings.TrimSpace(first + " " + last)
			if display == "" {
				display = email
			}
			status := strings.ToLower(attrString(e, "status"))
			if status == "" {
				status = "active"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  id,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       email,
				Status:      status,
			})
		}
		next := ""
		if len(resp.Data) >= pageSize {
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
// `sso_entity_id` into the shared SAML envelope used to broker Personio SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *PersonioAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *PersonioAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":            ProviderName,
		"auth_type":           "client_credentials",
		"client_id_short":     shortToken(secrets.ClientID),
		"client_secret_short": shortToken(secrets.ClientSecret),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*PersonioAccessConnector)(nil)
