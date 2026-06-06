// Package wave implements the access.AccessConnector contract for the
// Wave Financial GraphQL API.
//
// Wave does not expose a "team members" API; the closest available
// resource is the businesses connection on the authenticated user.
// This connector treats each business the calling token can act on as
// an IdentityTypeServiceAccount, mirroring the approach taken for
// Stripe Connect and PayPal partner integrations.
package wave

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
)

const (
	ProviderName = "wave"
	pageSize     = 50
)

var ErrNotImplemented = fmt.Errorf("wave: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type WaveAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *WaveAccessConnector { return &WaveAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("wave: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("wave: secrets is nil")
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
		return errors.New("wave: token is required")
	}
	return nil
}

func (c *WaveAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *WaveAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://gql.waveapps.com"
}

func (c *WaveAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *WaveAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

const businessesQuery = `query($first: Int!, $after: String) {
  businesses(first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node { id name isActive isArchived } }
  }
}`

type waveBusinessNode struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsActive   bool   `json:"isActive"`
	IsArchived bool   `json:"isArchived"`
}

type waveGraphQLResponse struct {
	Data struct {
		Businesses struct {
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
			Edges []struct {
				Node waveBusinessNode `json:"node"`
			} `json:"edges"`
		} `json:"businesses"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *WaveAccessConnector) postQuery(ctx context.Context, secrets Secrets, after string) (*waveGraphQLResponse, error) {
	vars := map[string]interface{}{"first": pageSize}
	if after != "" {
		vars["after"] = after
	} else {
		vars["after"] = nil
	}
	payload, _ := json.Marshal(map[string]interface{}{"query": businessesQuery, "variables": vars})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/graphql/public", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("wave: graphql: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wave: graphql status %d: %s", resp.StatusCode, string(body))
	}
	var parsed waveGraphQLResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("wave: decode graphql: %w", err)
	}
	if len(parsed.Errors) > 0 {
		return nil, fmt.Errorf("wave: graphql error: %s", parsed.Errors[0].Message)
	}
	return &parsed, nil
}

func (c *WaveAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.postQuery(ctx, secrets, ""); err != nil {
		return fmt.Errorf("wave: connect probe: %w", err)
	}
	return nil
}

func (c *WaveAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

func (c *WaveAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *WaveAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	for {
		resp, err := c.postQuery(ctx, secrets, cursor)
		if err != nil {
			return err
		}
		batch := make([]*access.Identity, 0, len(resp.Data.Businesses.Edges))
		for _, e := range resp.Data.Businesses.Edges {
			status := "active"
			if e.Node.IsArchived {
				status = "archived"
			} else if !e.Node.IsActive {
				status = "inactive"
			}
			batch = append(batch, &access.Identity{
				ExternalID:  e.Node.ID,
				Type:        access.IdentityTypeServiceAccount,
				DisplayName: e.Node.Name,
				Status:      status,
			})
		}
		next := ""
		if resp.Data.Businesses.PageInfo.HasNextPage {
			next = resp.Data.Businesses.PageInfo.EndCursor
		}
		if err := handler(batch, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

func (c *WaveAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *WaveAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*WaveAccessConnector)(nil)
