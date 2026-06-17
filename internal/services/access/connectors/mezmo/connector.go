// Package mezmo implements the access.AccessConnector contract for the
// Mezmo (formerly LogDNA) /v1/config/members API.
package mezmo

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

const ProviderName = "mezmo"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	ServiceKey string `json:"service_key"`
}

type MezmoAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *MezmoAccessConnector { return &MezmoAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("mezmo: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("mezmo: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["service_key"].(string); ok {
		s.ServiceKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ServiceKey) == "" {
		return errors.New("mezmo: service_key is required")
	}
	return nil
}

func (c *MezmoAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *MezmoAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.mezmo.com"
}

func (c *MezmoAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *MezmoAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "servicekey "+strings.TrimSpace(secrets.ServiceKey))
	return req, nil
}

func (c *MezmoAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("mezmo: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mezmo: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *MezmoAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *MezmoAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/v1/config/members"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("mezmo: connect probe: %w", err)
	}
	return nil
}

func (c *MezmoAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type mezmoMember struct {
	ID       string `json:"_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
}

func (c *MezmoAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MezmoAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := c.baseURL() + "/v1/config/members"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var members []mezmoMember
	if err := json.Unmarshal(body, &members); err != nil {
		// Some Mezmo accounts wrap the array in a top-level "members" field.
		var wrapper struct {
			Members []mezmoMember `json:"members"`
		}
		if err2 := json.Unmarshal(body, &wrapper); err2 != nil {
			return fmt.Errorf("mezmo: decode members: %w", err)
		}
		members = wrapper.Members
	}
	identities := make([]*access.Identity, 0, len(members))
	for _, m := range members {
		display := m.Name
		if display == "" {
			display = m.Email
		}
		status := "active"
		if m.Disabled {
			status = "disabled"
		}
		identities = append(identities, &access.Identity{
			ExternalID:  m.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.Email,
			Status:      status,
			RawData:     map[string]interface{}{"role": m.Role},
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Mezmo SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *MezmoAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *MezmoAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "service_key",
		"key_short": shortToken(secrets.ServiceKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*MezmoAccessConnector)(nil)
