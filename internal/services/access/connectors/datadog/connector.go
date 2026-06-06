// Package datadog implements the access.AccessConnector contract for the
// Datadog /api/v2/users API.
package datadog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"bytes"

	"net/url"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "datadog"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("datadog: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Site string `json:"site"` // datadoghq.com (default), datadoghq.eu, us3.datadoghq.com, etc.
}

type Secrets struct {
	APIKey         string `json:"api_key"`
	ApplicationKey string `json:"application_key"`
}

type DatadogAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DatadogAccessConnector { return &DatadogAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("datadog: config is nil")
	}
	var cfg Config
	if v, ok := raw["site"].(string); ok {
		cfg.Site = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("datadog: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	if v, ok := raw["application_key"].(string); ok {
		s.ApplicationKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("datadog: api_key is required")
	}
	if strings.TrimSpace(s.ApplicationKey) == "" {
		return errors.New("datadog: application_key is required")
	}
	return nil
}

func (c *DatadogAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DatadogAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	site := strings.TrimSpace(cfg.Site)
	if site == "" {
		site = "datadoghq.com"
	}
	return "https://api." + site
}

func (c *DatadogAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DatadogAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("DD-API-KEY", strings.TrimSpace(secrets.APIKey))
	req.Header.Set("DD-APPLICATION-KEY", strings.TrimSpace(secrets.ApplicationKey))
	return req, nil
}

// httpError is the typed error returned by do() for any non-2xx
// upstream response. It carries the HTTP status, the request path,
// and the (limited) response body so callers can reason about the
// failure without parsing the formatted error string. Callers that
// only care about the boolean err != nil signal continue to work
// because Error() still produces the original `status %d: %s` shape.
type httpError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("datadog: %s %s: status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

func (c *DatadogAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("datadog: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &httpError{
			Method:     req.Method,
			Path:       req.URL.Path,
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}
	return body, nil
}

func (c *DatadogAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *DatadogAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/api/v2/users?page%%5Bnumber%%5D=0&page%%5Bsize%%5D=1", c.baseURL(cfg))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("datadog: connect probe: %w", err)
	}
	return nil
}

func (c *DatadogAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type ddUser struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Email    string `json:"email"`
		Handle   string `json:"handle"`
		Name     string `json:"name"`
		Disabled bool   `json:"disabled"`
		Status   string `json:"status"`
	} `json:"attributes"`
}

type ddListResponse struct {
	Data []ddUser `json:"data"`
	Meta struct {
		Page struct {
			TotalCount int `json:"total_count"`
		} `json:"page"`
	} `json:"meta"`
}

func (c *DatadogAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *DatadogAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 0 {
			page = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/api/v2/users?page%%5Bnumber%%5D=%d&page%%5Bsize%%5D=%d", base, page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp ddListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("datadog: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
			display := u.Attributes.Name
			if display == "" {
				display = u.Attributes.Handle
			}
			if display == "" {
				display = u.Attributes.Email
			}
			status := "active"
			if u.Attributes.Disabled {
				status = "disabled"
			} else if u.Attributes.Status != "" {
				status = strings.ToLower(u.Attributes.Status)
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Attributes.Email,
				Status:      status,
			})
		}
		next := ""
		if (page+1)*pageSize < resp.Meta.Page.TotalCount && len(resp.Data) > 0 {
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

func (c *DatadogAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("datadog: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{"type": "users", "id": grant.UserExternalID}})
	urlStr := fmt.Sprintf("%s/api/v2/roles/%s/users", c.baseURL(cfg), url.PathEscape(grant.ResourceExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", secrets.APIKey)
	req.Header.Set("DD-APPLICATION-KEY", secrets.ApplicationKey)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("datadog: provision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("datadog: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *DatadogAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("datadog: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{"type": "users", "id": grant.UserExternalID}})
	urlStr := fmt.Sprintf("%s/api/v2/roles/%s/users", c.baseURL(cfg), url.PathEscape(grant.ResourceExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", secrets.APIKey)
	req.Header.Set("DD-APPLICATION-KEY", secrets.ApplicationKey)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("datadog: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("datadog: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *DatadogAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("datadog: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/api/v2/users/%s/roles", c.baseURL(cfg), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, nil
	}
	var out []access.Entitlement
	for _, r := range resp.Data {
		out = append(out, access.Entitlement{ResourceExternalID: r.ID, Role: r.Attributes.Name, Source: "direct"})
	}
	return out, nil
}
func (c *DatadogAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DatadogAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":              ProviderName,
		"auth_type":             "dd_keys",
		"api_key_short":         shortToken(secrets.APIKey),
		"application_key_short": shortToken(secrets.ApplicationKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*DatadogAccessConnector)(nil)
