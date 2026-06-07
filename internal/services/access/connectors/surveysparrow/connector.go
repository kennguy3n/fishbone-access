// Package surveysparrow implements the access.AccessConnector contract for SurveySparrow /v3/team
// with bearer auth + page/per_page pagination.
package surveysparrow

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
	ProviderName = "surveysparrow"
	pageSize     = 100
	// surveySparrowIdentitiesMaxPages caps SyncIdentities pagination as a
	// defense-in-depth guard against an upstream that never returns a
	// short final page. Mirrors splunkIdentitiesMaxPages in
	// splunk/connector.go.
	surveySparrowIdentitiesMaxPages = 2000
)

var ErrNotImplemented = fmt.Errorf("surveysparrow: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type SurveysparrowAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SurveysparrowAccessConnector { return &SurveysparrowAccessConnector{} }
func init()                              { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("surveysparrow: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("surveysparrow: secrets is nil")
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
		return errors.New("surveysparrow: token is required")
	}
	return nil
}

func (c *SurveysparrowAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SurveysparrowAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.surveysparrow.com"
}

func (c *SurveysparrowAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SurveysparrowAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *SurveysparrowAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("surveysparrow: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("surveysparrow: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *SurveysparrowAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SurveysparrowAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + ("/v3/team") + "?page=1&per_page=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("surveysparrow: connect probe: %w", err)
	}
	return nil
}

func (c *SurveysparrowAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type apiUser struct {
	ID    json.Number `json:"id"`
	Email string      `json:"email"`
	Name  string      `json:"name"`
}

type apiListResponse struct {
	Items []apiUser `json:"data"`
}

func (c *SurveysparrowAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SurveysparrowAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
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
	pathOnly := base + ("/v3/team")
	for pages := 0; pages < surveySparrowIdentitiesMaxPages; pages++ {
		q := url.Values{
			"page":     []string{fmt.Sprintf("%d", page)},
			"per_page": []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := pathOnly + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp apiListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("surveysparrow: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Items))
		for _, u := range resp.Items {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if len(resp.Items) == pageSize {
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
	return fmt.Errorf("surveysparrow: sync identities: pagination exceeded %d pages", surveySparrowIdentitiesMaxPages)
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker
// SurveySparrow SSO federation. When `sso_metadata_url` is blank the
// helper returns (nil, nil) and the caller gracefully downgrades.
func (c *SurveysparrowAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SurveysparrowAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*SurveysparrowAccessConnector)(nil)
