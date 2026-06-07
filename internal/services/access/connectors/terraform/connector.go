// Package terraform implements the access.AccessConnector contract for the
// Terraform Cloud organization-memberships API.
package terraform

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
	ProviderName = "terraform"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Organization string `json:"organization"`
}

type Secrets struct {
	Token string `json:"token"`
}

type TerraformAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *TerraformAccessConnector { return &TerraformAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("terraform: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization"].(string); ok {
		cfg.Organization = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("terraform: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Organization) == "" {
		return errors.New("terraform: organization is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("terraform: token is required")
	}
	return nil
}

func (c *TerraformAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *TerraformAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://app.terraform.io"
}

func (c *TerraformAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *TerraformAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *TerraformAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("terraform: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("terraform: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *TerraformAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *TerraformAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/api/v2/organizations/%s/organization-memberships?page%%5Bnumber%%5D=1&page%%5Bsize%%5D=1", c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.Organization)))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("terraform: connect probe: %w", err)
	}
	return nil
}

func (c *TerraformAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type tfResource struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Status string `json:"status"`
		Email  string `json:"email"`
	} `json:"attributes"`
	Relationships struct {
		User struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
		} `json:"user"`
	} `json:"relationships"`
}

type tfIncluded struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"attributes"`
}

type tfListResponse struct {
	Data     []tfResource `json:"data"`
	Included []tfIncluded `json:"included"`
	Meta     struct {
		Pagination struct {
			CurrentPage int `json:"current-page"`
			TotalPages  int `json:"total-pages"`
			TotalCount  int `json:"total-count"`
		} `json:"pagination"`
	} `json:"meta"`
}

func (c *TerraformAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *TerraformAccessConnector) SyncIdentities(
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
		path := fmt.Sprintf("%s/api/v2/organizations/%s/organization-memberships?page%%5Bnumber%%5D=%d&page%%5Bsize%%5D=%d&include=user",
			base, url.PathEscape(strings.TrimSpace(cfg.Organization)), page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp tfListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("terraform: decode memberships: %w", err)
		}
		users := make(map[string]tfIncluded, len(resp.Included))
		for _, inc := range resp.Included {
			if inc.Type == "users" {
				users[inc.ID] = inc
			}
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, m := range resp.Data {
			email := m.Attributes.Email
			display := email
			userID := m.Relationships.User.Data.ID
			if u, ok := users[userID]; ok {
				if u.Attributes.Email != "" {
					email = u.Attributes.Email
				}
				if u.Attributes.Username != "" {
					display = u.Attributes.Username
				}
			}
			status := strings.ToLower(m.Attributes.Status)
			if status == "" {
				status = "active"
			}
			externalID := userID
			if externalID == "" {
				externalID = m.ID
			}
			identities = append(identities, &access.Identity{
				ExternalID:  externalID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       email,
				Status:      status,
			})
		}
		next := ""
		if resp.Meta.Pagination.TotalPages > page {
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

// GetSSOMetadata returns Terraform Cloud SAML federation metadata when the
// operator supplied an `sso_metadata_url` in configRaw. Returns nil (and
// nil error) when the config does not advertise a metadata URL so callers
// downgrade to access.ErrSSOFederationUnsupported.
func (c *TerraformAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *TerraformAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*TerraformAccessConnector)(nil)
