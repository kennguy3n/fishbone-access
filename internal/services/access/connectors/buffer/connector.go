// Package buffer implements the access.AccessConnector contract for the
// Buffer /1/profiles.json endpoint. Buffer's social-profile API does not
// expose true paginated user lists; SyncIdentities returns each linked
// profile (which is the closest analogue to "user" in the Buffer model) in a
// single batch and is therefore minimal-page by design.
package buffer

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

const ProviderName = "buffer"

var ErrNotImplemented = fmt.Errorf("buffer: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type BufferAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *BufferAccessConnector { return &BufferAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("buffer: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("buffer: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error { return nil }
func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("buffer: token is required")
	}
	return nil
}

func (c *BufferAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *BufferAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.bufferapp.com"
}

func (c *BufferAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *BufferAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *BufferAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("buffer: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("buffer: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *BufferAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *BufferAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/1/user.json"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("buffer: connect probe: %w", err)
	}
	return nil
}

func (c *BufferAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type bufferProfile struct {
	ID          string `json:"id"`
	ServiceID   string `json:"service_id"`
	Service     string `json:"service"`
	ServiceName string `json:"service_username"`
	FormattedSN string `json:"formatted_username"`
	Disabled    bool   `json:"disabled"`
}

func (c *BufferAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *BufferAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// Buffer's API does not paginate /1/profiles.json — a single GET
	// returns the full list. Honour the contract by yielding everything
	// in one batch and signalling no continuation.
	fullURL := c.baseURL() + "/1/profiles.json"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var profiles []bufferProfile
	if err := json.Unmarshal(body, &profiles); err != nil {
		return fmt.Errorf("buffer: decode profiles: %w", err)
	}
	identities := make([]*access.Identity, 0, len(profiles))
	for _, p := range profiles {
		display := strings.TrimSpace(p.FormattedSN)
		if display == "" {
			display = p.ServiceName
		}
		if display == "" {
			display = p.ID
		}
		status := "active"
		if p.Disabled {
			status = "disabled"
		}
		identities = append(identities, &access.Identity{
			ExternalID:  p.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Status:      status,
		})
	}
	return handler(identities, "")
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// Buffer workspace. Buffer supports SAML 2.0 SSO via the platform
// admin console for paid plans; the connector forwards
// operator-supplied URLs verbatim via access.SSOMetadataFromConfig
// so the SSOFederationService can register a iam-core SAML broker.
// Returns (nil, nil) when the operator has not supplied a metadata
// URL so the caller downgrades gracefully.
func (c *BufferAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *BufferAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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
		// Never echo a short secret verbatim: GetCredentialsMetadata is a
		// non-sensitive fingerprint surfaced in the admin UI/logs, so a
		// ≤8-char token must be fully masked rather than returned as-is.
		return strings.Repeat("*", len(t))
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*BufferAccessConnector)(nil)
