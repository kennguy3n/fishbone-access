// Package gorgias implements the access.AccessConnector contract for the
// Gorgias /api/users API.
package gorgias

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "gorgias"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("gorgias: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Account string `json:"account"`
}

type Secrets struct {
	Email  string `json:"email"`
	APIKey string `json:"api_key"`
}

type GorgiasAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *GorgiasAccessConnector { return &GorgiasAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("gorgias: config is nil")
	}
	var cfg Config
	if v, ok := raw["account"].(string); ok {
		cfg.Account = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("gorgias: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["email"].(string); ok {
		s.Email = v
	}
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	acc := strings.TrimSpace(c.Account)
	if acc == "" {
		return errors.New("gorgias: account is required")
	}
	if !isDNSLabel(acc) {
		return errors.New("gorgias: account must be a single DNS label (letters, digits, hyphen)")
	}
	return nil
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

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Email) == "" {
		return errors.New("gorgias: email is required")
	}
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("gorgias: api_key is required")
	}
	return nil
}

func (c *GorgiasAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GorgiasAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + strings.TrimSpace(cfg.Account) + ".gorgias.com"
}

// sharedHTTPClient is reused across requests so the underlying
// http.Transport connection pool (keep-alives, TLS sessions) is shared
// rather than rebuilt on every call. http.Client is safe for concurrent
// use by multiple goroutines.
var sharedHTTPClient = &http.Client{Timeout: 30 * time.Second}

func (c *GorgiasAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return sharedHTTPClient
}

func (c *GorgiasAccessConnector) newRequest(ctx context.Context, cfg Config, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Gorgias-Account", strings.TrimSpace(cfg.Account))
	creds := strings.TrimSpace(secrets.Email) + ":" + strings.TrimSpace(secrets.APIKey)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *GorgiasAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gorgias: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gorgias: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *GorgiasAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GorgiasAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/api/users?page=1&per_page=1", c.baseURL(cfg))
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("gorgias: connect probe: %w", err)
	}
	return nil
}

func (c *GorgiasAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type gorgiasUser struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Name      string `json:"name"`
	Active    bool   `json:"active"`
	Role      string `json:"role"`
}

type gorgiasListResponse struct {
	Data []gorgiasUser `json:"data"`
	Meta struct {
		NextPage int `json:"next_page"`
	} `json:"meta"`
}

func (c *GorgiasAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GorgiasAccessConnector) SyncIdentities(
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
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/api/users?page=%d&per_page=%d", base, page, pageSize)
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp gorgiasListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("gorgias: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
			display := strings.TrimSpace(u.FirstName + " " + u.LastName)
			if display == "" {
				display = u.Name
			}
			if display == "" {
				display = u.Email
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			// ExternalID must be the email, not the numeric u.ID: it is
			// the key every membership operation consumes. ProvisionAccess
			// POSTs {email, role}; RevokeAccess and ListEntitlements resolve
			// the user via GET /api/users?email={id} and filter by
			// case-insensitive email match (findGorgiasUserID /
			// listGorgiasUsersByEmail). Keying the synced identity on the
			// numeric id would make those lookups silently miss (no email
			// match), turning revokes into no-ops and hiding entitlements.
			identities = append(identities, &access.Identity{
				ExternalID:  u.Email,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
				RawData:     map[string]interface{}{"role": u.Role, "id": u.ID},
			})
		}
		// Emit the checkpoint that matches the page the loop will fetch
		// next. Using the local `page+1` instead of the API-reported
		// `resp.Meta.NextPage` keeps the persisted checkpoint in lock-step
		// with the loop's own cursor, so a caller who persists the
		// checkpoint and resumes will not skip pages if the API ever
		// reports a NextPage that disagrees with the natural successor.
		hasMore := (resp.Meta.NextPage > 0 && len(resp.Data) > 0) || len(resp.Data) == pageSize
		next := ""
		if hasMore {
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

// Gorgias SSO federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *GorgiasAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *GorgiasAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "basic",
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

var _ access.AccessConnector = (*GorgiasAccessConnector)(nil)
