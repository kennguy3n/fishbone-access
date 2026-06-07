// Package square implements the access.AccessConnector contract for Square /v2/team-members/search with bearer auth + cursor pagination.
// /v2/team-members/search is a POST endpoint that accepts a JSON body with a search query and pagination cursor.
package square

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	ProviderName = "square"
	pageSize     = 100
	// squareIdentitiesMaxPages caps SyncIdentities pagination as a
	// defense-in-depth guard against an upstream that never returns an
	// empty cursor. Mirrors splunkIdentitiesMaxPages in
	// splunk/connector.go.
	squareIdentitiesMaxPages = 2000
)

var ErrNotImplemented = fmt.Errorf("square: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type SquareAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SquareAccessConnector { return &SquareAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("square: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("square: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("square: token is required")
	}
	return nil
}

func (c *SquareAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SquareAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://connect.squareup.com"
}

func (c *SquareAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SquareAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *SquareAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("square: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("square: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, httputil.SafeErrorBody(body))
	}
	return body, nil
}

func (c *SquareAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SquareAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_ = cfg
	probe := c.baseURL() + "/v2/team-members/search"
	body, err := json.Marshal(map[string]interface{}{"limit": 1})
	if err != nil {
		return fmt.Errorf("square: encode connect body: %w", err)
	}
	req, err := c.newRequest(ctx, secrets, http.MethodPost, probe, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("square: connect probe: %w", err)
	}
	return nil
}

func (c *SquareAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type squareUser struct {
	ID    string `json:"id"`
	Email string `json:"email_address"`
	Name  string `json:"given_name"`
}

type squareListResponse struct {
	Items  []squareUser `json:"team_members"`
	Cursor string       `json:"cursor"`
}

func (c *SquareAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SquareAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_ = cfg
	cursor := strings.TrimSpace(checkpoint)
	base := c.baseURL()
	path := base + "/v2/team-members/search"
	for pages := 0; pages < squareIdentitiesMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqBody := map[string]interface{}{
			"limit": pageSize,
		}
		if cursor != "" {
			reqBody["cursor"] = cursor
		}
		encoded, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("square: encode search body: %w", err)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodPost, path, bytes.NewReader(encoded))
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp squareListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("square: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Items))
		for _, u := range resp.Items {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if strings.TrimSpace(resp.Cursor) != "" {
			next = strings.TrimSpace(resp.Cursor)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
	return fmt.Errorf("square: sync identities: pagination exceeded %d pages", squareIdentitiesMaxPages)
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// Square workspace. Square supports SAML 2.0 SSO via the platform
// admin console for paid plans; the connector forwards
// operator-supplied URLs verbatim via access.SSOMetadataFromConfig
// so the SSOFederationService can register a iam-core SAML broker.
// Returns (nil, nil) when the operator has not supplied a metadata
// URL so the caller downgrades gracefully.
func (c *SquareAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SquareAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*SquareAccessConnector)(nil)
