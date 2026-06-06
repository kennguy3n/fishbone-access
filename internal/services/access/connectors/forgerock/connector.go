// Package forgerock implements the access.AccessConnector contract for the
// ForgeRock AM/IDM /openidm/managed/user endpoint.
//
// ForgeRock IDM exposes managed objects via CREST queries: the connector
// passes `_queryFilter=true&_pageSize=N`, follows the
// `_pagedResultsCookie` continuation token between requests, and stops
// when the cookie is empty.
package forgerock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "forgerock"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("forgerock: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// Endpoint is the operator-controlled ForgeRock IDM URL (e.g.
	// https://idm.corp.example). Required.
	Endpoint string `json:"endpoint"`
}

type Secrets struct {
	Token string `json:"token"`
}

type ForgeRockAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *ForgeRockAccessConnector { return &ForgeRockAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("forgerock: config is nil")
	}
	var cfg Config
	if v, ok := raw["endpoint"].(string); ok {
		cfg.Endpoint = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("forgerock: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	e := strings.TrimSpace(c.Endpoint)
	if e == "" {
		return errors.New("forgerock: endpoint is required")
	}
	u, err := url.Parse(e)
	if err != nil {
		return fmt.Errorf("forgerock: endpoint must be a well-formed URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("forgerock: endpoint must use https://")
	}
	if u.User != nil {
		return errors.New("forgerock: endpoint must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("forgerock: endpoint must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("forgerock: endpoint must not contain a query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("forgerock: endpoint must contain a host")
	}
	if net.ParseIP(host) != nil {
		return errors.New("forgerock: endpoint host must be a domain name, not an IP literal")
	}
	if !isHost(host) {
		return errors.New("forgerock: endpoint host must contain only DNS label characters and dots")
	}
	return nil
}

func isHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("forgerock: token is required")
	}
	return nil
}

func (c *ForgeRockAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *ForgeRockAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
}

func (c *ForgeRockAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *ForgeRockAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *ForgeRockAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("forgerock: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forgerock: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *ForgeRockAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *ForgeRockAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/openidm/managed/user?_queryFilter=true&_pageSize=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("forgerock: connect probe: %w", err)
	}
	return nil
}

func (c *ForgeRockAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type forgeRockUser struct {
	ID         string `json:"_id"`
	UserName   string `json:"userName"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"sn"`
	Email      string `json:"mail"`
	AccStatus  string `json:"accountStatus"`
}

type forgeRockListResponse struct {
	Result               []forgeRockUser `json:"result"`
	PagedResultsCookie   string          `json:"pagedResultsCookie"`
	RemainingPagedResult int             `json:"remainingPagedResults"`
}

func (c *ForgeRockAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *ForgeRockAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cookie := strings.TrimSpace(checkpoint)
	base := c.baseURL(cfg)
	for {
		q := url.Values{
			"_queryFilter": []string{"true"},
			"_pageSize":    []string{fmt.Sprintf("%d", pageSize)},
		}
		if cookie != "" {
			q.Set("_pagedResultsCookie", cookie)
		}
		fullURL := base + "/openidm/managed/user?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp forgeRockListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("forgerock: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Result))
		for _, u := range resp.Result {
			external := u.ID
			if external == "" {
				external = u.UserName
			}
			display := strings.TrimSpace(strings.TrimSpace(u.GivenName) + " " + strings.TrimSpace(u.FamilyName))
			if display == "" {
				display = u.UserName
			}
			status := "active"
			switch strings.ToLower(strings.TrimSpace(u.AccStatus)) {
			case "inactive", "disabled", "suspended":
				status = "disabled"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  external,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := strings.TrimSpace(resp.PagedResultsCookie)
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cookie = next
	}
}

// GetSSOMetadata advertises ForgeRock AM OIDC discovery metadata.
// ForgeRock exposes the standard OIDC `.well-known/openid-configuration`
// document at the configured endpoint, which iam-core imports as an
// OIDC IdP broker. Returns (nil, nil) when no endpoint is configured.
func (c *ForgeRockAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		return nil, nil
	}
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: endpoint + "/.well-known/openid-configuration",
		EntityID:    endpoint,
		SSOLoginURL: endpoint + "/oauth2/authorize",
	}, nil
}

func (c *ForgeRockAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*ForgeRockAccessConnector)(nil)
