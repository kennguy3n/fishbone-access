// Package splunk implements the access.AccessConnector contract for the
// Splunk Cloud /services/authentication/users API.
package splunk

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	ProviderName = "splunk"
	pageSize     = 100
)

// splunkIdentitiesMaxPages caps the per-call page walk in
// SyncIdentities (and the CountIdentities-via-SyncIdentities path).
// Even with an aggressively oversized Splunk org (100k+ users at
// pageSize=100), legitimate pagination terminates well below this
// bound. The cap is a defense-in-depth guard against a misconfigured
// / malicious upstream returning a perpetually inflated paging.Total
// combined with a non-empty page on every request — the secondary
// next-empty guard would not catch that. Mirrors
// splunkGroupsMaxPages=2000 in groups.go and splunkAuditMaxPages=200
// in audit.go.
const splunkIdentitiesMaxPages = 2000

var ErrNotImplemented = fmt.Errorf("splunk: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	BaseURL string `json:"base_url"`
}

type Secrets struct {
	Token string `json:"token"`
}

type SplunkAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SplunkAccessConnector { return &SplunkAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("splunk: config is nil")
	}
	var cfg Config
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("splunk: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("splunk: base_url is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("splunk: token is required")
	}
	return nil
}

func (c *SplunkAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SplunkAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
}

func (c *SplunkAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SplunkAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *SplunkAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("splunk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("splunk: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, httputil.SafeErrorBody(body))
	}
	return body, nil
}

func (c *SplunkAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SplunkAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/services/authentication/users?output_mode=json&count=1&offset=0", c.baseURL(cfg))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("splunk: connect probe: %w", err)
	}
	return nil
}

func (c *SplunkAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type splunkEntry struct {
	Name    string `json:"name"`
	Content struct {
		Email    string `json:"email"`
		RealName string `json:"realname"`
		Locked   bool   `json:"locked-out"`
	} `json:"content"`
}

type splunkListResponse struct {
	Entry  []splunkEntry `json:"entry"`
	Paging struct {
		Total   int `json:"total"`
		PerPage int `json:"perPage"`
		Offset  int `json:"offset"`
	} `json:"paging"`
}

func (c *SplunkAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SplunkAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	base := c.baseURL(cfg)
	for pages := 0; pages < splunkIdentitiesMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/services/authentication/users?output_mode=json&count=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp splunkListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("splunk: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Entry))
		for _, e := range resp.Entry {
			display := e.Content.RealName
			if display == "" {
				display = e.Name
			}
			status := "active"
			if e.Content.Locked {
				status = "locked"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  e.Name,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       e.Content.Email,
				Status:      status,
			})
		}
		next := ""
		if offset+len(resp.Entry) < resp.Paging.Total && len(resp.Entry) > 0 {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
	return fmt.Errorf("splunk: sync identities: pagination exceeded %d pages (server returned non-terminating paging.total)", splunkIdentitiesMaxPages)
}

// ProvisionAccess, RevokeAccess, ListEntitlements: see advanced.go.

func (c *SplunkAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SplunkAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*SplunkAccessConnector)(nil)
