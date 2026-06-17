// Package slack_enterprise implements the access.AccessConnector contract for the
// Slack Enterprise Grid SCIM /scim/v2/Users API.
package slack_enterprise

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
	ProviderName = "slack_enterprise"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type SlackEnterpriseAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SlackEnterpriseAccessConnector { return &SlackEnterpriseAccessConnector{} }
func init() {
	access.RegisterAccessConnector(ProviderName, New())
}

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("slack_enterprise: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("slack_enterprise: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("slack_enterprise: token is required")
	}
	return nil
}

func (c *SlackEnterpriseAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SlackEnterpriseAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.slack.com"
}

func (c *SlackEnterpriseAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SlackEnterpriseAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/scim+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *SlackEnterpriseAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack_enterprise: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("slack_enterprise: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *SlackEnterpriseAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SlackEnterpriseAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/scim/v2/Users?startIndex=1&count=1", c.baseURL())
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("slack_enterprise: connect probe: %w", err)
	}
	return nil
}

func (c *SlackEnterpriseAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type scimUser struct {
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Active      bool        `json:"active"`
	Emails      []scimEmail `json:"emails"`
}

type scimListResponse struct {
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []scimUser `json:"Resources"`
}

func (c *SlackEnterpriseAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SlackEnterpriseAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startIndex := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &startIndex)
		if startIndex < 1 {
			startIndex = 1
		}
	}
	base := c.baseURL()
	for {
		path := fmt.Sprintf("%s/scim/v2/Users?startIndex=%d&count=%d", base, startIndex, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp scimListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("slack_enterprise: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Resources))
		for _, u := range resp.Resources {
			email := ""
			for _, e := range u.Emails {
				if e.Primary {
					email = e.Value
					break
				}
			}
			if email == "" && len(u.Emails) > 0 {
				email = u.Emails[0].Value
			}
			display := u.DisplayName
			if display == "" {
				display = u.UserName
			}
			if display == "" {
				display = email
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       email,
				Status:      status,
			})
		}
		next := ""
		fetched := startIndex - 1 + len(resp.Resources)
		if len(resp.Resources) == pageSize && fetched < resp.TotalResults {
			next = fmt.Sprintf("%d", startIndex+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		startIndex += pageSize
	}
}

// GetSSOMetadata returns Slack Enterprise Grid SAML federation metadata
// when the operator supplied an `sso_metadata_url` in configRaw. Returns
// nil (and nil error) when the config does not advertise a metadata URL
// so callers downgrade to access.ErrSSOFederationUnsupported.
func (c *SlackEnterpriseAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SlackEnterpriseAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*SlackEnterpriseAccessConnector)(nil)
