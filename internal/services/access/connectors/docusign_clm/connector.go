// Package docusign_clm implements the access.AccessConnector contract for the
// DocuSign Clm /v201411/users API.
package docusign_clm

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
	ProviderName = "docusign_clm"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	AccountEnvironment string `json:"account_environment"`
	Region             string `json:"region"`
}

type Secrets struct {
	Token string `json:"token"`
}

type DocuSignCLMAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DocuSignCLMAccessConnector { return &DocuSignCLMAccessConnector{} }
func init()                            { access.RegisterAccessConnector(ProviderName, New()) }

var allowedEnvs = map[string]struct{}{
	"production": {},
	"demo":       {},
}

var allowedRegions = map[string]struct{}{
	"na": {},
	"eu": {},
}

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("docusign_clm: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_environment"].(string); ok {
		cfg.AccountEnvironment = v
	}
	if v, ok := raw["region"].(string); ok {
		cfg.Region = v
	}
	if strings.TrimSpace(cfg.AccountEnvironment) == "" {
		cfg.AccountEnvironment = "production"
	}
	if strings.TrimSpace(cfg.Region) == "" {
		cfg.Region = "na"
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("docusign_clm: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	env := strings.ToLower(strings.TrimSpace(c.AccountEnvironment))
	if _, ok := allowedEnvs[env]; !ok {
		return fmt.Errorf("docusign_clm: account_environment must be one of production|demo, got %q", c.AccountEnvironment)
	}
	region := strings.ToLower(strings.TrimSpace(c.Region))
	if _, ok := allowedRegions[region]; !ok {
		return fmt.Errorf("docusign_clm: region must be one of na|eu, got %q", c.Region)
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("docusign_clm: token is required")
	}
	return nil
}

func (c *DocuSignCLMAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DocuSignCLMAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	env := strings.ToLower(strings.TrimSpace(cfg.AccountEnvironment))
	region := strings.ToLower(strings.TrimSpace(cfg.Region))
	switch {
	case env == "demo" && region == "eu":
		return "https://apiuateu11.springcm.com"
	case env == "demo":
		return "https://apiuatna11.springcm.com"
	case region == "eu":
		return "https://apieu11.springcm.com"
	}
	return "https://apina11.springcm.com"
}

func (c *DocuSignCLMAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DocuSignCLMAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *DocuSignCLMAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("docusign_clm: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docusign_clm: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *DocuSignCLMAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *DocuSignCLMAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	q := url.Values{"page": []string{"1"}, "per_page": []string{"1"}}
	probe := c.baseURL(cfg) + "/v201411/users?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("docusign_clm: connect probe: %w", err)
	}
	return nil
}

func (c *DocuSignCLMAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type docusignClmUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Status    bool   `json:"active"`
}

type docusignClmListResponse struct {
	Items []docusignClmUser `json:"users"`
}

func (c *DocuSignCLMAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *DocuSignCLMAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
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
	base := c.baseURL(cfg)
	for {
		q := url.Values{
			"page":     []string{fmt.Sprintf("%d", page)},
			"per_page": []string{fmt.Sprintf("%d", pageSize)},
		}
		path := base + "/v201411/users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp docusignClmListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("docusign_clm: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Items))
		for _, u := range resp.Items {
			display := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
			if display == "" {
				display = u.Email
			}
			status := "active"
			if !u.Status {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
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
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// DocuSign CLM workspace. DocuSign CLM supports SAML 2.0 SSO via
// the CLM admin console; the connector forwards the operator-supplied
// URLs verbatim via access.SSOMetadataFromConfig so the
// SSOFederationService can register a iam-core SAML broker. Returns
// (nil, nil) when the operator has not supplied a metadata URL so
// the caller gracefully downgrades.
func (c *DocuSignCLMAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DocuSignCLMAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*DocuSignCLMAccessConnector)(nil)
