// Package stripe implements the access.AccessConnector contract for Stripe
// Connect platforms.
//
// Stripe does not expose a public REST API for dashboard team members
// (see https://stripe.com/docs/api). The closest thing the platform can
// pull is the list of connected merchant accounts via /v1/accounts —
// those are the businesses (merchants) that have authorized the platform
// account to act on their behalf, not the human users who can sign into
// the dashboard. This connector therefore syncs connected accounts as
// IdentityTypeServiceAccount records (one per merchant) rather than
// pretending to enumerate dashboard team members.
package stripe

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

const (
	ProviderName = "stripe"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("stripe: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	SecretKey string `json:"secret_key"`
}

type StripeAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *StripeAccessConnector { return &StripeAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("stripe: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("stripe: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["secret_key"].(string); ok {
		s.SecretKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.SecretKey) == "" {
		return errors.New("stripe: secret_key is required")
	}
	return nil
}

func (c *StripeAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *StripeAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.stripe.com"
}

func (c *StripeAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *StripeAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.SecretKey))
	return req, nil
}

func (c *StripeAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("stripe: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("stripe: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *StripeAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *StripeAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/v1/accounts?limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("stripe: connect probe: %w", err)
	}
	return nil
}

func (c *StripeAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type stripeAccount struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	BusinessProfile struct {
		Name string `json:"name"`
	} `json:"business_profile"`
	Type           string `json:"type"`
	Country        string `json:"country"`
	ChargesEnabled bool   `json:"charges_enabled"`
	PayoutsEnabled bool   `json:"payouts_enabled"`
}

type stripeListResponse struct {
	Object  string          `json:"object"`
	HasMore bool            `json:"has_more"`
	Data    []stripeAccount `json:"data"`
}

func (c *StripeAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *StripeAccessConnector) SyncIdentities(
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
	base := c.baseURL()
	for {
		path := fmt.Sprintf("%s/v1/accounts?limit=%d", base, pageSize)
		if cursor != "" {
			path += "&starting_after=" + cursor
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp stripeListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("stripe: decode accounts: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, a := range resp.Data {
			display := a.BusinessProfile.Name
			if display == "" {
				display = a.Email
			}
			if display == "" {
				display = a.ID
			}
			status := "active"
			if !a.ChargesEnabled || !a.PayoutsEnabled {
				status = "restricted"
			}
			identities = append(identities, &access.Identity{
				ExternalID: a.ID,
				// Connected accounts are merchant businesses, not human
				// users; service_account is the closest fit in the
				// IdentityType enum.
				Type:        access.IdentityTypeServiceAccount,
				DisplayName: display,
				Email:       a.Email,
				Status:      status,
				RawData:     map[string]interface{}{"type": a.Type, "country": a.Country},
			})
		}
		next := ""
		if resp.HasMore && len(resp.Data) > 0 {
			next = resp.Data[len(resp.Data)-1].ID
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Stripe SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *StripeAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *StripeAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "secret_key",
		"key_short": shortToken(secrets.SecretKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*StripeAccessConnector)(nil)
