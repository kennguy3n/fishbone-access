// Package new_relic implements the access.AccessConnector contract for
// the New Relic NerdGraph users API.
package new_relic

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

const ProviderName = "new_relic"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Region string `json:"region"` // "us" (default) or "eu".
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type NewRelicAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *NewRelicAccessConnector { return &NewRelicAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("new_relic: config is nil")
	}
	var cfg Config
	if v, ok := raw["region"].(string); ok {
		cfg.Region = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("new_relic: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("new_relic: api_key is required")
	}
	return nil
}

func (c *NewRelicAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *NewRelicAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if strings.EqualFold(strings.TrimSpace(cfg.Region), "eu") {
		return "https://api.eu.newrelic.com"
	}
	return "https://api.newrelic.com"
}

func (c *NewRelicAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *NewRelicAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

const usersQuery = `query($cursor: String) {
  actor {
    organization {
      userManagement {
        authenticationDomains {
          authenticationDomains {
            users(cursor: $cursor) {
              users { id name email }
              nextCursor
            }
          }
        }
      }
    }
  }
}`

type nrUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type nrUsersBlock struct {
	Users      []nrUser `json:"users"`
	NextCursor string   `json:"nextCursor"`
}

type nrAuthDomain struct {
	Users nrUsersBlock `json:"users"`
}

type nrGraphQLResponse struct {
	Data struct {
		Actor struct {
			Organization struct {
				UserManagement struct {
					AuthenticationDomains struct {
						AuthenticationDomains []nrAuthDomain `json:"authenticationDomains"`
					} `json:"authenticationDomains"`
				} `json:"userManagement"`
			} `json:"organization"`
		} `json:"actor"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *NewRelicAccessConnector) postQuery(ctx context.Context, cfg Config, secrets Secrets, cursor string) (*nrGraphQLResponse, error) {
	payload := map[string]interface{}{
		"query":     usersQuery,
		"variables": map[string]interface{}{"cursor": cursor},
	}
	if cursor == "" {
		payload["variables"] = map[string]interface{}{"cursor": nil}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(cfg)+"/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("API-Key", strings.TrimSpace(secrets.APIKey))
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("new_relic: graphql: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("new_relic: graphql status %d: %s", resp.StatusCode, string(respBody))
	}
	var parsed nrGraphQLResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("new_relic: decode graphql: %w", err)
	}
	if len(parsed.Errors) > 0 {
		return nil, fmt.Errorf("new_relic: graphql error: %s", parsed.Errors[0].Message)
	}
	return &parsed, nil
}

func (c *NewRelicAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.postQuery(ctx, cfg, secrets, ""); err != nil {
		return fmt.Errorf("new_relic: connect probe: %w", err)
	}
	return nil
}

func (c *NewRelicAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

func (c *NewRelicAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *NewRelicAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	for {
		resp, err := c.postQuery(ctx, cfg, secrets, cursor)
		if err != nil {
			return err
		}
		var (
			batch   []*access.Identity
			nextCur string
		)
		// The NerdGraph users connection takes a single $cursor variable
		// shared across authenticationDomains, so this connector is only
		// guaranteed correct for organizations with one auth domain. Pick
		// the first non-empty nextCursor encountered to make pagination
		// deterministic when more than one domain is returned.
		for _, dom := range resp.Data.Actor.Organization.UserManagement.AuthenticationDomains.AuthenticationDomains {
			for _, u := range dom.Users.Users {
				display := u.Name
				if display == "" {
					display = u.Email
				}
				batch = append(batch, &access.Identity{
					ExternalID:  u.ID,
					Type:        access.IdentityTypeUser,
					DisplayName: display,
					Email:       u.Email,
					Status:      "active",
				})
			}
			if nextCur == "" && dom.Users.NextCursor != "" {
				nextCur = dom.Users.NextCursor
			}
		}
		if err := handler(batch, nextCur); err != nil {
			return err
		}
		if nextCur == "" {
			return nil
		}
		cursor = nextCur
	}
}

// ProvisionAccess, RevokeAccess, ListEntitlements: see advanced.go.
// GetSSOMetadata: see sso.go.

func (c *NewRelicAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *NewRelicAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_key",
		"token_short": shortToken(secrets.APIKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*NewRelicAccessConnector)(nil)
