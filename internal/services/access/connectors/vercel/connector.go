// Package vercel implements the access.AccessConnector contract for the
// Vercel teams-membership API.
package vercel

import (
	"context"
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
	ProviderName   = "vercel"
	defaultBaseURL = "https://api.vercel.com"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TeamID string `json:"team_id,omitempty"`
}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type VercelAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *VercelAccessConnector { return &VercelAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, nil
	}
	var cfg Config
	if v, ok := raw["team_id"].(string); ok {
		cfg.TeamID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("vercel: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("vercel: api_token is required")
	}
	return nil
}

func (c *VercelAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *VercelAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *VercelAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *VercelAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *VercelAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("vercel: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vercel: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *VercelAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *VercelAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := "/v2/user"
	if cfg.TeamID != "" {
		path = "/v2/teams/" + cfg.TeamID
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("vercel: connect probe: %w", err)
	}
	return nil
}

func (c *VercelAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type vercelMembersResponse struct {
	Members    []vercelMember `json:"members"`
	Pagination struct {
		Next string `json:"next,omitempty"`
	} `json:"pagination"`
}

type vercelMember struct {
	UID       string `json:"uid"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Confirmed bool   `json:"confirmed"`
}

type vercelUserResponse struct {
	User struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Username string `json:"username"`
	} `json:"user"`
}

func (c *VercelAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	if cfg.TeamID == "" {
		return 1, nil
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/v2/teams/"+cfg.TeamID+"/members?limit=50")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var resp vercelMembersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("vercel: decode members: %w", err)
	}
	return len(resp.Members), nil
}

func (c *VercelAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if cfg.TeamID == "" {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, "/v2/user")
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp vercelUserResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("vercel: decode user: %w", err)
		}
		display := resp.User.Name
		if display == "" {
			display = resp.User.Username
		}
		return handler([]*access.Identity{{
			ExternalID:  resp.User.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       resp.User.Email,
			Status:      "active",
		}}, "")
	}
	basePath := "/v2/teams/" + cfg.TeamID + "/members?limit=50"
	path := basePath
	if checkpoint != "" {
		path = basePath + "&until=" + checkpoint
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp vercelMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("vercel: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Members))
		for _, m := range resp.Members {
			display := m.Name
			if display == "" {
				display = m.Username
			}
			status := "active"
			if !m.Confirmed {
				status = "pending"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.UID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      status,
				RawData:     map[string]interface{}{"role": m.Role},
			})
		}
		next := resp.Pagination.Next
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		path = basePath + "&until=" + next
	}
}

// GetSSOMetadata returns the operator-supplied SAML metadata for
// Vercel team-level SSO (Enterprise plan). When `sso_metadata_url` is
// blank the helper returns (nil, nil) and the caller gracefully
// downgrades.
func (c *VercelAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *VercelAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_token",
		"token_short": shortToken(secrets.APIToken),
	}
	if cfg.TeamID != "" {
		out["team_id"] = cfg.TeamID
	}
	return out, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*VercelAccessConnector)(nil)
