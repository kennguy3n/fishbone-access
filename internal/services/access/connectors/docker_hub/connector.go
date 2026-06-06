// Package docker_hub implements the access.AccessConnector contract for
// Docker Hub organization members. Docker Hub uses a JWT bearer token
// flow: POST /v2/users/login with username/password (or PAT) returns a
// JWT, which is then used for subsequent /v2/orgs/{org}/members calls.
package docker_hub

import (
	"bytes"
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
	ProviderName = "docker_hub"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Organization string `json:"organization"`
}

type Secrets struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DockerHubAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DockerHubAccessConnector { return &DockerHubAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("docker_hub: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization"].(string); ok {
		cfg.Organization = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("docker_hub: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["username"].(string); ok {
		s.Username = v
	}
	if v, ok := raw["password"].(string); ok {
		s.Password = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Organization) == "" {
		return errors.New("docker_hub: organization is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Username) == "" {
		return errors.New("docker_hub: username is required")
	}
	if strings.TrimSpace(s.Password) == "" {
		return errors.New("docker_hub: password is required")
	}
	return nil
}

func (c *DockerHubAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DockerHubAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://hub.docker.com"
}

func (c *DockerHubAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DockerHubAccessConnector) login(ctx context.Context, secrets Secrets) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"username": strings.TrimSpace(secrets.Username),
		"password": strings.TrimSpace(secrets.Password),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/v2/users/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("docker_hub: login: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("docker_hub: login: status %d", resp.StatusCode)
	}
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("docker_hub: decode login: %w", err)
	}
	if parsed.Token == "" {
		return "", errors.New("docker_hub: login returned empty token")
	}
	return parsed.Token, nil
}

func (c *DockerHubAccessConnector) newRequest(ctx context.Context, token, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "JWT "+token)
	return req, nil
}

func (c *DockerHubAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker_hub: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker_hub: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *DockerHubAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *DockerHubAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.login(ctx, secrets); err != nil {
		return fmt.Errorf("docker_hub: connect probe: %w", err)
	}
	return nil
}

func (c *DockerHubAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type dockerHubMember struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type dockerHubListResponse struct {
	Count    int               `json:"count"`
	Next     string            `json:"next"`
	Previous string            `json:"previous"`
	Results  []dockerHubMember `json:"results"`
}

func (c *DockerHubAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *DockerHubAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return err
	}
	base := c.baseURL()
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = fmt.Sprintf("%s/v2/orgs/%s/members?page=1&page_size=%d", base, url.PathEscape(strings.TrimSpace(cfg.Organization)), pageSize)
	}
	for {
		req, err := c.newRequest(ctx, token, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp dockerHubListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("docker_hub: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Results))
		for _, m := range resp.Results {
			display := m.FullName
			if display == "" {
				display = m.Username
			}
			externalID := m.ID
			if externalID == "" {
				externalID = m.Username
			}
			identities = append(identities, &access.Identity{
				ExternalID:  externalID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      "active",
				RawData:     map[string]interface{}{"role": m.Role},
			})
		}
		next := strings.TrimSpace(resp.Next)
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

// GetSSOMetadata returns Docker Hub organisation SAML federation metadata
// when the operator supplied an `sso_metadata_url` in configRaw. Returns
// nil (and nil error) when the config does not advertise a metadata URL
// so callers downgrade to access.ErrSSOFederationUnsupported.
func (c *DockerHubAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DockerHubAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"auth_type":      "jwt",
		"username_short": shortToken(secrets.Username),
		"password_short": shortToken(secrets.Password),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*DockerHubAccessConnector)(nil)
