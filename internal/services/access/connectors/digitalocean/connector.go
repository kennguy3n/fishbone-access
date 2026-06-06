// Package digitalocean implements the access.AccessConnector contract for
// the DigitalOcean team-membership API.
package digitalocean

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
	ProviderName   = "digitalocean"
	defaultBaseURL = "https://api.digitalocean.com"
)

var ErrNotImplemented = fmt.Errorf("digitalocean: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type DigitalOceanAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DigitalOceanAccessConnector { return &DigitalOceanAccessConnector{} }
func init()                             { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("digitalocean: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("digitalocean: api_token is required")
	}
	return nil
}

func (c *DigitalOceanAccessConnector) Validate(_ context.Context, _, secretsRaw map[string]interface{}) error {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *DigitalOceanAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *DigitalOceanAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DigitalOceanAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *DigitalOceanAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("digitalocean: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("digitalocean: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *DigitalOceanAccessConnector) decodeBoth(secretsRaw map[string]interface{}) (Secrets, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Secrets{}, err
	}
	return s, nil
}

func (c *DigitalOceanAccessConnector) Connect(ctx context.Context, _, secretsRaw map[string]interface{}) error {
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/v2/account")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("digitalocean: connect probe: %w", err)
	}
	return nil
}

func (c *DigitalOceanAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type doAccount struct {
	Account struct {
		Email  string `json:"email"`
		UUID   string `json:"uuid"`
		Status string `json:"status"`
	} `json:"account"`
}

type doMembersResponse struct {
	Members []doMember `json:"members"`
	Meta    struct {
		Total int `json:"total"`
	} `json:"meta"`
	Links struct {
		Pages struct {
			Next string `json:"next,omitempty"`
		} `json:"pages"`
	} `json:"links"`
}

type doMember struct {
	UUID      string `json:"uuid"`
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Status    string `json:"status"`
}

func (c *DigitalOceanAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/v2/team/members?per_page=1")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		// Fallback to /v2/account when /v2/team/members is not
		// authorised (tokens scoped to a non-team account).
		req2, err2 := c.newRequest(ctx, secrets, http.MethodGet, "/v2/account")
		if err2 != nil {
			return 0, err2
		}
		if _, err := c.do(req2); err != nil {
			return 0, err
		}
		return 1, nil
	}
	var resp doMembersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("digitalocean: decode members: %w", err)
	}
	return resp.Meta.Total, nil
}

func (c *DigitalOceanAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	path := "/v2/team/members?per_page=50"
	if checkpoint != "" {
		path = nextPath(checkpoint)
	}
	first := true
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			if first {
				req2, err2 := c.newRequest(ctx, secrets, http.MethodGet, "/v2/account")
				if err2 != nil {
					return err2
				}
				body2, err := c.do(req2)
				if err != nil {
					return err
				}
				var acct doAccount
				if err := json.Unmarshal(body2, &acct); err != nil {
					return fmt.Errorf("digitalocean: decode account: %w", err)
				}
				return handler([]*access.Identity{{
					ExternalID:  acct.Account.UUID,
					Type:        access.IdentityTypeUser,
					DisplayName: acct.Account.Email,
					Email:       acct.Account.Email,
					Status:      strings.ToLower(acct.Account.Status),
				}}, "")
			}
			return err
		}
		first = false
		var resp doMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("digitalocean: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Members))
		for _, m := range resp.Members {
			display := strings.TrimSpace(m.FirstName + " " + m.LastName)
			if display == "" {
				display = m.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.UUID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      strings.ToLower(m.Status),
			})
		}
		next := resp.Links.Pages.Next
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		path = nextPath(next)
	}
}

func nextPath(next string) string {
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return next
	}
	p := u.Path
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	// Pagination links are re-joined onto baseURL(), so the result must
	// be host-rooted. DigitalOcean returns absolute links today (whose
	// url.Path already starts with "/"), but a relative link such as
	// "v2/teams?page=2" would otherwise concatenate straight onto the
	// host ("https://api.digitalocean.comv2/teams"). Force a leading
	// slash so either form yields a valid URL.
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// GetSSOMetadata returns the operator-supplied SAML metadata for
// DigitalOcean team-level SSO. When `sso_metadata_url` is blank the
// helper returns (nil, nil) and the caller gracefully downgrades.
func (c *DigitalOceanAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DigitalOceanAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	secrets, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_token",
		"token_short": shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*DigitalOceanAccessConnector)(nil)
