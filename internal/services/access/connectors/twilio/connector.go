// Package twilio implements the access.AccessConnector contract for the
// Twilio /2010-04-01/Accounts/{sid}/Users.json endpoint with HTTP Basic
// (account_sid : auth_token) auth and Page/PageSize pagination.
package twilio

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
	ProviderName = "twilio"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccountSID string `json:"account_sid"`
	AuthToken  string `json:"auth_token"`
}

type TwilioAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *TwilioAccessConnector { return &TwilioAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("twilio: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("twilio: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["account_sid"].(string); ok {
		s.AccountSID = v
	}
	if v, ok := raw["auth_token"].(string); ok {
		s.AuthToken = v
	}
	return s, nil
}

func (c Config) validate() error { return nil }
func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccountSID) == "" {
		return errors.New("twilio: account_sid is required")
	}
	if strings.TrimSpace(s.AuthToken) == "" {
		return errors.New("twilio: auth_token is required")
	}
	return nil
}

func (c *TwilioAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *TwilioAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.twilio.com"
}

func (c *TwilioAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *TwilioAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(strings.TrimSpace(secrets.AccountSID), strings.TrimSpace(secrets.AuthToken))
	return req, nil
}

func (c *TwilioAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("twilio: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("twilio: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *TwilioAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *TwilioAccessConnector) usersPath(secrets Secrets) string {
	return "/2010-04-01/Accounts/" + url.PathEscape(strings.TrimSpace(secrets.AccountSID)) + "/Users.json"
}

func (c *TwilioAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + c.usersPath(secrets) + "?Page=0&PageSize=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("twilio: connect probe: %w", err)
	}
	return nil
}

func (c *TwilioAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type twilioUser struct {
	SID          string `json:"sid"`
	FriendlyName string `json:"friendly_name"`
	Identity     string `json:"identity"`
	Email        string `json:"email"`
}

type twilioListResponse struct {
	Users []twilioUser `json:"users"`
}

func (c *TwilioAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *TwilioAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 0 {
			page = 0
		}
	}
	base := c.baseURL()
	pathOnly := c.usersPath(secrets)
	for {
		q := url.Values{
			"Page":     []string{fmt.Sprintf("%d", page)},
			"PageSize": []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := base + pathOnly + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp twilioListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("twilio: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := strings.TrimSpace(u.FriendlyName)
			if display == "" {
				display = u.Identity
			}
			if display == "" {
				display = u.SID
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.SID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if len(resp.Users) == pageSize {
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

func (c *TwilioAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *TwilioAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":          ProviderName,
		"auth_type":         "http_basic_sid_token",
		"account_sid_short": shortToken(secrets.AccountSID),
		"auth_token_short":  shortToken(secrets.AuthToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*TwilioAccessConnector)(nil)
