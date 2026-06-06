// Package liquidplanner implements the access.AccessConnector contract for the
// LiquidPlanner /api/v1/workspaces/{workspace_id}/members API.
package liquidplanner

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

const ProviderName = "liquidplanner"

var ErrNotImplemented = fmt.Errorf("liquidplanner: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	WorkspaceID string `json:"workspace_id"`
}

type Secrets struct {
	Token string `json:"token"`
}

type LiquidPlannerAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *LiquidPlannerAccessConnector { return &LiquidPlannerAccessConnector{} }
func init()                              { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("liquidplanner: config is nil")
	}
	var cfg Config
	if v, ok := raw["workspace_id"].(string); ok {
		cfg.WorkspaceID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("liquidplanner: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	id := strings.TrimSpace(c.WorkspaceID)
	if id == "" {
		return errors.New("liquidplanner: workspace_id is required")
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return errors.New("liquidplanner: workspace_id must be numeric")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("liquidplanner: token is required")
	}
	return nil
}

func (c *LiquidPlannerAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *LiquidPlannerAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://app.liquidplanner.com"
}

func (c *LiquidPlannerAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *LiquidPlannerAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *LiquidPlannerAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("liquidplanner: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("liquidplanner: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *LiquidPlannerAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *LiquidPlannerAccessConnector) membersURL(cfg Config) string {
	return fmt.Sprintf("%s/api/v1/workspaces/%s/members", c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.WorkspaceID)))
}

func (c *LiquidPlannerAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.membersURL(cfg))
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("liquidplanner: connect probe: %w", err)
	}
	return nil
}

func (c *LiquidPlannerAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type liquidplannerMember struct {
	ID          int    `json:"id"`
	UserName    string `json:"user_name"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	EmailAddr   string `json:"email"`
	AccessLevel string `json:"access_level"`
	Disabled    bool   `json:"disabled"`
}

func (c *LiquidPlannerAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *LiquidPlannerAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.membersURL(cfg))
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var members []liquidplannerMember
	if err := json.Unmarshal(body, &members); err != nil {
		return fmt.Errorf("liquidplanner: decode members: %w", err)
	}
	identities := make([]*access.Identity, 0, len(members))
	for _, m := range members {
		display := strings.TrimSpace(m.FirstName + " " + m.LastName)
		if display == "" {
			display = m.UserName
		}
		if display == "" {
			display = m.EmailAddr
		}
		status := "active"
		if m.Disabled {
			status = "disabled"
		}
		identities = append(identities, &access.Identity{
			ExternalID:  fmt.Sprintf("%d", m.ID),
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.EmailAddr,
			Status:      status,
			RawData:     map[string]interface{}{"access_level": m.AccessLevel},
		})
	}
	return handler(identities, "")
}

func (c *LiquidPlannerAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *LiquidPlannerAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "bearer",
		"token_short": shortToken(secrets.Token),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*LiquidPlannerAccessConnector)(nil)
