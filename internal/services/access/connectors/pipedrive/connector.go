// Package pipedrive implements the access.AccessConnector contract for the
// Pipedrive users API.
package pipedrive

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
	ProviderName   = "pipedrive"
	defaultBaseURL = "https://api.pipedrive.com/v1"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type PipedriveAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *PipedriveAccessConnector { return &PipedriveAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(_ map[string]interface{}) (Config, error) { return Config{}, nil }

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("pipedrive: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("pipedrive: api_token is required")
	}
	return nil
}

func (c *PipedriveAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *PipedriveAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *PipedriveAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// newRequest builds an authenticated Pipedrive request. The api_token is sent
// via the Authorization header (Pipedrive accepts "Bearer <api_token>" for both
// v1 and v2 endpoints) so it never lands in the URL — keeping it out of
// *url.Error.Error() messages and any subsequent log lines.
func (c *PipedriveAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *PipedriveAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("pipedrive: %s %s: %w", req.Method, req.URL.Path, sanitizeURLError(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("pipedrive: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *PipedriveAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
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

func (c *PipedriveAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/users/me")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("pipedrive: connect probe: %w", err)
	}
	return nil
}

func (c *PipedriveAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type pipedriveUsersResponse struct {
	Success bool            `json:"success"`
	Data    []pipedriveUser `json:"data"`
	// Pipedrive's /users endpoint returns the full list at once, but
	// some collection endpoints expose additional_data.pagination.
	AdditionalData struct {
		Pagination struct {
			Start                 int  `json:"start"`
			Limit                 int  `json:"limit"`
			MoreItemsInCollection bool `json:"more_items_in_collection"`
			NextStart             int  `json:"next_start,omitempty"`
		} `json:"pagination"`
	} `json:"additional_data"`
}

type pipedriveUser struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Active  bool   `json:"active_flag"`
	IsAdmin int    `json:"is_admin"`
	IsYou   bool   `json:"is_you,omitempty"`
}

func (c *PipedriveAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *PipedriveAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	start := checkpoint
	for {
		path := "/users"
		if start != "" {
			path += "?start=" + start
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp pipedriveUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("pipedrive: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			display := u.Name
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", u.ID),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if resp.AdditionalData.Pagination.MoreItemsInCollection {
			next = fmt.Sprintf("%d", resp.AdditionalData.Pagination.NextStart)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		start = next
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Pipedrive SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *PipedriveAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *PipedriveAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_token",
		"token_short": shortToken(s.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

// sanitizeURLError strips the URL component from *url.Error so that any
// query-string-borne secrets (defence-in-depth — we already moved the token
// to the Authorization header) cannot leak through wrapped error messages.
func sanitizeURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

var _ access.AccessConnector = (*PipedriveAccessConnector)(nil)
