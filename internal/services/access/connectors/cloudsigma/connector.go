// Package cloudsigma implements the access.AccessConnector contract for the
// CloudSigma profile API (single-user).
package cloudsigma

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

const ProviderName = "cloudsigma"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Region string `json:"region"`
}

type Secrets struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CloudSigmaAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *CloudSigmaAccessConnector { return &CloudSigmaAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("cloudsigma: config is nil")
	}
	var cfg Config
	if v, ok := raw["region"].(string); ok {
		cfg.Region = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("cloudsigma: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["email"].(string); ok {
		s.Email = v
	}
	if v, ok := raw["password"].(string); ok {
		s.Password = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Region) == "" {
		return errors.New("cloudsigma: region is required (e.g. zrh, wdc, sjc)")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Email) == "" {
		return errors.New("cloudsigma: email is required")
	}
	if strings.TrimSpace(s.Password) == "" {
		return errors.New("cloudsigma: password is required")
	}
	return nil
}

func (c *CloudSigmaAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *CloudSigmaAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + cfg.Region + ".cloudsigma.com"
}

func (c *CloudSigmaAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func basicAuthHeader(email, password string) string {
	creds := strings.TrimSpace(email) + ":" + strings.TrimSpace(password)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func (c *CloudSigmaAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", basicAuthHeader(secrets.Email, secrets.Password))
	return req, nil
}

func (c *CloudSigmaAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudsigma: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudsigma: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *CloudSigmaAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *CloudSigmaAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/2.0/profile/"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("cloudsigma: connect probe: %w", err)
	}
	return nil
}

func (c *CloudSigmaAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type cloudSigmaProfile struct {
	UUID      string `json:"uuid"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	State     string `json:"state"`
}

func (c *CloudSigmaAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *CloudSigmaAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := c.baseURL(cfg) + "/api/2.0/profile/"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var profile cloudSigmaProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return fmt.Errorf("cloudsigma: decode profile: %w", err)
	}
	display := strings.TrimSpace(profile.FirstName + " " + profile.LastName)
	if display == "" {
		display = profile.Email
	}
	id := profile.UUID
	if id == "" {
		id = profile.Email
	}
	status := "active"
	if profile.State != "" && profile.State != "REGULAR" && profile.State != "active" {
		status = strings.ToLower(profile.State)
	}
	identities := []*access.Identity{
		{
			ExternalID:  id,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       profile.Email,
			Status:      status,
		},
	}
	return handler(identities, "")
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker CloudSigma SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *CloudSigmaAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *CloudSigmaAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"region":         cfg.Region,
		"email":          secrets.Email,
		"auth_type":      "basic",
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

var _ access.AccessConnector = (*CloudSigmaAccessConnector)(nil)
