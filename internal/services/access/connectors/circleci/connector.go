// Package circleci implements the access.AccessConnector contract for the
// CircleCI v2 API.
//
// The CircleCI v2 API does not expose a "list org members" endpoint.
// /api/v2/me/collaborations returns the list of organizations + accounts
// the calling token can act on; this connector treats each collaboration
// as a service-account-style identity (one row per org the token has
// access to). Operators that need full org-member sync should use the
// GitHub / GitLab connectors that drive CircleCI access in the first
// place.
package circleci

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

const ProviderName = "circleci"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type CircleCIAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *CircleCIAccessConnector { return &CircleCIAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("circleci: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("circleci: secrets is nil")
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
		return errors.New("circleci: token is required")
	}
	return nil
}

func (c *CircleCIAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *CircleCIAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://circleci.com"
}

func (c *CircleCIAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *CircleCIAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Circle-Token", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *CircleCIAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("circleci: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("circleci: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *CircleCIAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *CircleCIAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/api/v2/me/collaborations"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("circleci: connect probe: %w", err)
	}
	return nil
}

func (c *CircleCIAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type circleCollab struct {
	ID        string `json:"id"`
	VCSType   string `json:"vcs_type"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	AvatarURL string `json:"avatar_url"`
}

func (c *CircleCIAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *CircleCIAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := c.baseURL() + "/api/v2/me/collaborations"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var collabs []circleCollab
	if err := json.Unmarshal(body, &collabs); err != nil {
		return fmt.Errorf("circleci: decode collaborations: %w", err)
	}
	identities := make([]*access.Identity, 0, len(collabs))
	for _, col := range collabs {
		display := col.Name
		if display == "" {
			display = col.Slug
		}
		extID := col.ID
		if extID == "" {
			extID = col.Slug
		}
		identities = append(identities, &access.Identity{
			ExternalID:  extID,
			Type:        access.IdentityTypeServiceAccount,
			DisplayName: display,
			Status:      "active",
			RawData:     map[string]interface{}{"vcs_type": col.VCSType, "slug": col.Slug},
		})
	}
	return handler(identities, "")
}

// ProvisionAccess, RevokeAccess, ListEntitlements: see advanced.go.

func (c *CircleCIAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *CircleCIAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "circle_token",
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

var _ access.AccessConnector = (*CircleCIAccessConnector)(nil)
