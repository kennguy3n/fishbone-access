// Package basecamp implements the access.AccessConnector contract for the
// Basecamp 3 /people.json API.
package basecamp

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

const ProviderName = "basecamp"

var ErrNotImplemented = fmt.Errorf("basecamp: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	AccountID string `json:"account_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type BasecampAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *BasecampAccessConnector { return &BasecampAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("basecamp: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_id"].(string); ok {
		cfg.AccountID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("basecamp: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	id := strings.TrimSpace(c.AccountID)
	if id == "" {
		return errors.New("basecamp: account_id is required")
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return errors.New("basecamp: account_id must be numeric")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("basecamp: access_token is required")
	}
	return nil
}

func (c *BasecampAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *BasecampAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://3.basecampapi.com/" + url.PathEscape(strings.TrimSpace(cfg.AccountID))
}

func (c *BasecampAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *BasecampAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "shieldnet360-access (security@uney.com)")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *BasecampAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("basecamp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("basecamp: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

// doWithLink performs the request and returns the response body together
// with the rel="next" URL parsed from the RFC 5988 Link header, so
// collection endpoints (e.g. /people.json) can be fully paginated.
func (c *BasecampAccessConnector) doWithLink(req *http.Request) ([]byte, string, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("basecamp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("basecamp: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nextLinkFromHeader(resp.Header.Get("Link")), nil
}

// nextLinkFromHeader extracts the rel="next" URL from an RFC 5988 Link
// header (Basecamp's documented pagination mechanism), returning "" when
// there is no further page.
func nextLinkFromHeader(link string) string {
	for _, part := range strings.Split(link, ",") {
		segments := strings.Split(part, ";")
		if len(segments) < 2 {
			continue
		}
		urlPart := strings.TrimSpace(segments[0])
		if !strings.HasPrefix(urlPart, "<") || !strings.HasSuffix(urlPart, ">") {
			continue
		}
		for _, attr := range segments[1:] {
			if v := strings.TrimSpace(attr); v == `rel="next"` || v == "rel=next" {
				return urlPart[1 : len(urlPart)-1]
			}
		}
	}
	return ""
}

func (c *BasecampAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *BasecampAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/people.json"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("basecamp: connect probe: %w", err)
	}
	return nil
}

func (c *BasecampAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type basecampPerson struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	EmailAddress string `json:"email_address"`
	TitleClient  string `json:"title"`
	Admin        bool   `json:"admin"`
	Owner        bool   `json:"owner"`
	Bot          bool   `json:"bot"`
}

func (c *BasecampAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *BasecampAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// Basecamp paginates /people.json via the RFC 5988 Link header; a
	// single GET only returns the first page, silently truncating larger
	// directories. Follow rel="next" until it is absent so the full
	// directory is enumerated. An incoming checkpoint (a previously
	// returned next-page URL) resumes mid-directory.
	nextURL := c.baseURL(cfg) + "/people.json"
	if cp := strings.TrimSpace(checkpoint); cp != "" {
		nextURL = cp
	}
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, next, err := c.doWithLink(req)
		if err != nil {
			return err
		}
		var people []basecampPerson
		if err := json.Unmarshal(body, &people); err != nil {
			return fmt.Errorf("basecamp: decode people: %w", err)
		}
		identities := make([]*access.Identity, 0, len(people))
		for _, p := range people {
			display := p.Name
			if display == "" {
				display = p.EmailAddress
			}
			idType := access.IdentityTypeUser
			if p.Bot {
				idType = access.IdentityTypeServiceAccount
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", p.ID),
				Type:        idType,
				DisplayName: display,
				Email:       p.EmailAddress,
				Status:      "active",
				RawData:     map[string]interface{}{"admin": p.Admin, "owner": p.Owner, "title": p.TitleClient},
			})
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		nextURL = next
	}
	return nil
}

// Basecamp SSO federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *BasecampAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *BasecampAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "oauth2",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*BasecampAccessConnector)(nil)
