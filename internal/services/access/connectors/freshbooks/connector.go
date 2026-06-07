// Package freshbooks implements the access.AccessConnector contract for the
// FreshBooks accounting API.
package freshbooks

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
	ProviderName = "freshbooks"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("freshbooks: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	AccountID string `json:"account_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type FreshBooksAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *FreshBooksAccessConnector { return &FreshBooksAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("freshbooks: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_id"].(string); ok {
		cfg.AccountID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("freshbooks: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.AccountID) == "" {
		return errors.New("freshbooks: account_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("freshbooks: access_token is required")
	}
	return nil
}

func (c *FreshBooksAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *FreshBooksAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.freshbooks.com"
}

func (c *FreshBooksAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *FreshBooksAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Api-Version", "alpha")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *FreshBooksAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("freshbooks: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("freshbooks: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *FreshBooksAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *FreshBooksAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/auth/api/v1/users/me"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("freshbooks: connect probe: %w", err)
	}
	return nil
}

func (c *FreshBooksAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type fbStaff struct {
	ID        int    `json:"id"`
	UserID    int    `json:"userid"`
	Email     string `json:"email"`
	FirstName string `json:"fname"`
	LastName  string `json:"lname"`
	Active    bool   `json:"active"`
}

type fbStaffResponse struct {
	Response struct {
		Result struct {
			Staff   []fbStaff `json:"staff"`
			Page    int       `json:"page"`
			Pages   int       `json:"pages"`
			PerPage int       `json:"per_page"`
			Total   int       `json:"total"`
		} `json:"result"`
	} `json:"response"`
}

func (c *FreshBooksAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *FreshBooksAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 1 {
			page = 1
		}
	}
	base := c.baseURL()
	for {
		path := fmt.Sprintf("%s/accounting/account/%s/users/staffs?page=%d&per_page=%d",
			base, url.PathEscape(strings.TrimSpace(cfg.AccountID)), page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp fbStaffResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("freshbooks: decode staff: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Response.Result.Staff))
		for _, s := range resp.Response.Result.Staff {
			display := strings.TrimSpace(s.FirstName + " " + s.LastName)
			if display == "" {
				display = s.Email
			}
			status := "active"
			if !s.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", s.ID),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       s.Email,
				Status:      status,
			})
		}
		next := ""
		pages := resp.Response.Result.Pages
		if pages > 0 && page < pages {
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

// FreshBooks SSO federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *FreshBooksAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *FreshBooksAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"account_id":  cfg.AccountID,
		"auth_type":   "oauth2",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*FreshBooksAccessConnector)(nil)
