// Package braze implements the access.AccessConnector contract for the
// Braze /scim/v2/Users SCIM API.
package braze

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
	ProviderName = "braze"
	pageSize     = 100

	// brazeSyncMaxPages bounds the startIndex pagination walk as
	// defense-in-depth, matching azureSyncMaxPages / basecampSyncMaxPages.
	// The loop also stops on a short page (and when fetched reaches
	// totalResults) and honours ctx cancellation via the request context;
	// SyncIdentities reports each page's startIndex to the handler as a
	// checkpoint, so reaching the cap merely defers the remainder to the
	// next sync cycle.
	brazeSyncMaxPages = 10000
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Cluster string `json:"cluster"`
}

type Secrets struct {
	Token string `json:"token"`
}

type BrazeAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *BrazeAccessConnector { return &BrazeAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("braze: config is nil")
	}
	var cfg Config
	if v, ok := raw["cluster"].(string); ok {
		cfg.Cluster = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("braze: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

// allowedClusters mirrors Braze's published instance suffixes; restricting the
// set keeps the URL safe even though we already validate via DNS-label rules.
var allowedClusters = map[string]bool{
	"iad-01": true, "iad-02": true, "iad-03": true, "iad-04": true,
	"iad-05": true, "iad-06": true, "iad-07": true, "iad-08": true,
	"fra-01": true, "fra-02": true,
}

func (c Config) validate() error {
	cl := strings.TrimSpace(c.Cluster)
	if cl == "" {
		return errors.New("braze: cluster is required (e.g. iad-01, fra-01)")
	}
	if !isDNSLabel(cl) {
		return errors.New("braze: cluster must be a single DNS label")
	}
	if !allowedClusters[cl] {
		return fmt.Errorf("braze: cluster %q not in known Braze instance set", cl)
	}
	return nil
}

func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("braze: token is required")
	}
	return nil
}

func (c *BrazeAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *BrazeAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://rest." + strings.TrimSpace(cfg.Cluster) + ".braze.com"
}

func (c *BrazeAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *BrazeAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/scim+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *BrazeAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("braze: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("braze: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *BrazeAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *BrazeAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	q := url.Values{"startIndex": []string{"1"}, "count": []string{"1"}}
	probe := c.baseURL(cfg) + "/scim/v2/Users?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("braze: connect probe: %w", err)
	}
	return nil
}

func (c *BrazeAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type scimUser struct {
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Active      bool        `json:"active"`
	Emails      []scimEmail `json:"emails"`
}

type scimListResponse struct {
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []scimUser `json:"Resources"`
}

func (c *BrazeAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *BrazeAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startIndex := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &startIndex)
		if startIndex < 1 {
			startIndex = 1
		}
	}
	base := c.baseURL(cfg)
	for pageCount := 0; pageCount < brazeSyncMaxPages; pageCount++ {
		q := url.Values{
			"startIndex": []string{fmt.Sprintf("%d", startIndex)},
			"count":      []string{fmt.Sprintf("%d", pageSize)},
		}
		path := base + "/scim/v2/Users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp scimListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("braze: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Resources))
		for _, u := range resp.Resources {
			email := ""
			for _, e := range u.Emails {
				if e.Primary {
					email = e.Value
					break
				}
			}
			if email == "" && len(u.Emails) > 0 {
				email = u.Emails[0].Value
			}
			display := u.DisplayName
			if display == "" {
				display = u.UserName
			}
			if display == "" {
				display = email
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       email,
				Status:      status,
			})
		}
		next := ""
		fetched := startIndex - 1 + len(resp.Resources)
		if len(resp.Resources) == pageSize && fetched < resp.TotalResults {
			next = fmt.Sprintf("%d", startIndex+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		startIndex += pageSize
	}
	// Defensive page cap reached; the last handler call carried a
	// non-empty checkpoint, so the next sync cycle resumes from there.
	return nil
}

// Braze SSO federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *BrazeAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *BrazeAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "scim_bearer",
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

var _ access.AccessConnector = (*BrazeAccessConnector)(nil)
