// Package heroku implements the access.AccessConnector contract for the
// Heroku Platform API.
package heroku

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

// teamPath builds the URL path for a Heroku team, escaping the
// operator-supplied team name so names containing URL-sensitive
// characters ("/", "%", "?") cannot corrupt the request path. Mirrors
// the escaping already applied by teamMembersURL/teamMemberURL in
// advanced.go so every Heroku endpoint treats TeamName consistently.
func teamPath(team string) string {
	return "/teams/" + url.PathEscape(strings.TrimSpace(team))
}

const (
	ProviderName   = "heroku"
	defaultBaseURL = "https://api.heroku.com"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TeamName string `json:"team_name,omitempty"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type HerokuAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *HerokuAccessConnector { return &HerokuAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, nil
	}
	var cfg Config
	if v, ok := raw["team_name"].(string); ok {
		cfg.TeamName = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("heroku: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("heroku: api_key is required")
	}
	return nil
}

func (c *HerokuAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *HerokuAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *HerokuAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *HerokuAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *HerokuAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("heroku: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("heroku: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *HerokuAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *HerokuAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := "/account"
	if cfg.TeamName != "" {
		path = teamPath(cfg.TeamName)
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("heroku: connect probe: %w", err)
	}
	return nil
}

func (c *HerokuAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type herokuTeamMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
	User  struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
	} `json:"user"`
}

type herokuAccount struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

func (c *HerokuAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	if cfg.TeamName == "" {
		return 1, nil
	}
	members, err := c.listTeamMembers(ctx, secrets, cfg.TeamName)
	if err != nil {
		return 0, err
	}
	return len(members), nil
}

// listTeamMembers returns every member of a Heroku team, following
// Range/Next-Range pagination so teams larger than a single page are counted
// and synced in full. Reading only the first page (the previous behaviour)
// silently dropped every member beyond Heroku's default page size.
func (c *HerokuAccessConnector) listTeamMembers(ctx context.Context, secrets Secrets, team string) ([]herokuTeamMember, error) {
	var members []herokuTeamMember
	if _, err := c.doPaged(ctx, secrets, "", teamPath(team)+"/members", func(body []byte) error {
		var page []herokuTeamMember
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("heroku: decode members: %w", err)
		}
		members = append(members, page...)
		return nil
	}); err != nil {
		return nil, err
	}
	return members, nil
}

func (c *HerokuAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if cfg.TeamName == "" {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, "/account")
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var acct herokuAccount
		if err := json.Unmarshal(body, &acct); err != nil {
			return fmt.Errorf("heroku: decode account: %w", err)
		}
		display := acct.Name
		if display == "" {
			display = acct.Email
		}
		return handler([]*access.Identity{{
			ExternalID:  acct.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       acct.Email,
			Status:      "active",
		}}, "")
	}
	members, err := c.listTeamMembers(ctx, secrets, cfg.TeamName)
	if err != nil {
		return err
	}
	identities := make([]*access.Identity, 0, len(members))
	for _, m := range members {
		display := m.User.Name
		if display == "" {
			display = m.Email
		}
		extID := m.User.ID
		if extID == "" {
			extID = m.ID
		}
		identities = append(identities, &access.Identity{
			ExternalID:  extID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.Email,
			Status:      "active",
			RawData:     map[string]interface{}{"role": m.Role},
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata returns the operator-supplied SAML metadata URL for
// Heroku Enterprise teams. Heroku federates SSO via SAML 2.0 with
// metadata hosted by the customer's IdP; when `sso_metadata_url` is
// blank the helper returns (nil, nil) and the caller gracefully
// downgrades.
func (c *HerokuAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *HerokuAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_key",
		"token_short": shortToken(secrets.APIKey),
	}
	if cfg.TeamName != "" {
		out["team_name"] = cfg.TeamName
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

var _ access.AccessConnector = (*HerokuAccessConnector)(nil)
