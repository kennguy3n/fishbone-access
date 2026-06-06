// Package openai implements the access.AccessConnector contract for the
// OpenAI Organization /v1/organization/users endpoint.
//
// The OpenAI Organization API returns a list-style envelope with
// `{ "data": [...], "has_more": bool, "last_id": "user_..." }`. The
// connector forwards `last_id` as the `after` cursor and stops when
// `has_more` is false. The `limit` query parameter caps the page size.
package openai

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	ProviderName = "openai"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("openai: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// SAMLMetadataURL points at the OpenAI-issued SAML 2.0 metadata
	// document for the organization (rendered in the OpenAI admin
	// console under SSO settings). When set, the connector advertises
	// OpenAI SAML metadata via GetSSOMetadata.
	SAMLMetadataURL string `json:"saml_metadata_url,omitempty"`
	// SAMLEntityID is the IdP entity ID configured for the organization.
	// Optional — when empty the metadata URL is used as the entity ID.
	SAMLEntityID string `json:"saml_entity_id,omitempty"`
}

type Secrets struct {
	Token string `json:"token"`
}

type OpenAIAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *OpenAIAccessConnector { return &OpenAIAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("openai: config is nil")
	}
	var cfg Config
	if v, ok := raw["saml_metadata_url"].(string); ok {
		cfg.SAMLMetadataURL = v
	}
	if v, ok := raw["saml_entity_id"].(string); ok {
		cfg.SAMLEntityID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("openai: secrets is nil")
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
		return errors.New("openai: token is required")
	}
	return nil
}

func (c *OpenAIAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *OpenAIAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.openai.com"
}

// doHTTP routes the request through the injected test httpClient when
// present, otherwise through the shared RetryClient so production
// traffic reuses the connection pool (keep-alive, TLS sessions) and
// gets the 429/5xx retry-with-jitter policy.
func (c *OpenAIAccessConnector) doHTTP(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	return sharedRetryClient.Do(req.Context(), req)
}

// sharedRetryClient is a package-level singleton so the underlying
// *http.Client connection pool is reused across requests rather than
// rebuilt per call.
var sharedRetryClient = httputil.NewRetryClient(30 * time.Second)

func (c *OpenAIAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *OpenAIAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doHTTP(req)
	if err != nil {
		return nil, fmt.Errorf("openai: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openai: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *OpenAIAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *OpenAIAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/v1/organization/users?limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("openai: connect probe: %w", err)
	}
	return nil
}

func (c *OpenAIAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type openAIUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

type openAIListResponse struct {
	Data    []openAIUser `json:"data"`
	HasMore bool         `json:"has_more"`
	LastID  string       `json:"last_id"`
}

func (c *OpenAIAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *OpenAIAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	after := strings.TrimSpace(checkpoint)
	for {
		q := url.Values{
			"limit": []string{fmt.Sprintf("%d", pageSize)},
		}
		if after != "" {
			q.Set("after", after)
		}
		fullURL := c.baseURL() + "/v1/organization/users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp openAIListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("openai: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
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
		if resp.HasMore && strings.TrimSpace(resp.LastID) != "" {
			next = strings.TrimSpace(resp.LastID)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		after = next
	}
}

// GetSSOMetadata advertises OpenAI organization SAML metadata when
// the connector is configured with a saml_metadata_url. OpenAI
// Enterprise renders the metadata document per-organization; the
// operator wires the URL via config. Returns (nil, nil) when no
// metadata URL is set so callers treat the connector as
// SSO-unsupported.
func (c *OpenAIAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	metaURL := strings.TrimSpace(cfg.SAMLMetadataURL)
	if metaURL == "" {
		return nil, nil
	}
	entity := strings.TrimSpace(cfg.SAMLEntityID)
	if entity == "" {
		entity = metaURL
	}
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: metaURL,
		EntityID:    entity,
	}, nil
}

func (c *OpenAIAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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
	if t == "" {
		return ""
	}
	// Never echo a token verbatim. Production tokens are far longer than
	// 8 chars, but a misconfigured/test token must not leak in full
	// through GetCredentialsMetadata, so short tokens are fully masked.
	if len(t) <= 8 {
		return "***"
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*OpenAIAccessConnector)(nil)
