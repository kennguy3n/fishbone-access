// Package billdotcom implements the access.AccessConnector contract for the
// Bill.com /v3/users API using session-based auth.
package billdotcom

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
	ProviderName = "billdotcom"
	pageSize     = 100

	// billdotcomSyncMaxPages bounds the start/offset pagination walk as
	// defense-in-depth, matching azureSyncMaxPages / basecampSyncMaxPages.
	// The loop also stops on a short page and honours ctx cancellation via
	// the request context; SyncIdentities reports each page's start offset
	// to the handler as a checkpoint, so reaching the cap merely defers the
	// remainder to the next sync cycle.
	billdotcomSyncMaxPages = 10000
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrgID string `json:"org_id"`
}

type Secrets struct {
	DevKey       string `json:"dev_key"`
	SessionToken string `json:"session_token"`
}

type BillDotComAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *BillDotComAccessConnector { return &BillDotComAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("billdotcom: config is nil")
	}
	var cfg Config
	if v, ok := raw["org_id"].(string); ok {
		cfg.OrgID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("billdotcom: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["dev_key"].(string); ok {
		s.DevKey = v
	}
	if v, ok := raw["session_token"].(string); ok {
		s.SessionToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	id := strings.TrimSpace(c.OrgID)
	if id == "" {
		return errors.New("billdotcom: org_id is required")
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-' || r == '_') {
			return errors.New("billdotcom: org_id must be alphanumeric")
		}
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.DevKey) == "" {
		return errors.New("billdotcom: dev_key is required")
	}
	if strings.TrimSpace(s.SessionToken) == "" {
		return errors.New("billdotcom: session_token is required")
	}
	return nil
}

func (c *BillDotComAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *BillDotComAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.bill.com"
}

func (c *BillDotComAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *BillDotComAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("devKey", strings.TrimSpace(secrets.DevKey))
	req.Header.Set("sessionId", strings.TrimSpace(secrets.SessionToken))
	return req, nil
}

func (c *BillDotComAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("billdotcom: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("billdotcom: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *BillDotComAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *BillDotComAccessConnector) buildPath(cfg Config) string {
	return "/v3/orgs/" + url.PathEscape(strings.TrimSpace(cfg.OrgID)) + "/users"
}

func (c *BillDotComAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	q := url.Values{"max": []string{"1"}, "start": []string{"0"}}
	probe := c.baseURL() + c.buildPath(cfg) + "?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("billdotcom: connect probe: %w", err)
	}
	return nil
}

func (c *BillDotComAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type billUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Active    bool   `json:"active"`
}

type billListResponse struct {
	Users []billUser `json:"users"`
}

func (c *BillDotComAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *BillDotComAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	start := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &start)
		if start < 0 {
			start = 0
		}
	}
	base := c.baseURL()
	for pageCount := 0; pageCount < billdotcomSyncMaxPages; pageCount++ {
		q := url.Values{
			"start": []string{fmt.Sprintf("%d", start)},
			"max":   []string{fmt.Sprintf("%d", pageSize)},
		}
		path := base + c.buildPath(cfg) + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp billListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("billdotcom: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			display := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
			if display == "" {
				display = u.Email
			}
			status := "active"
			if !u.Active {
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
		if len(resp.Users) == pageSize {
			next = fmt.Sprintf("%d", start+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		start += pageSize
	}
	// Defensive page cap reached; the last handler call carried a
	// non-empty checkpoint, so the next sync cycle resumes from there.
	return nil
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Bill.com SSO
// federation. When `sso_metadata_url` is blank the helper returns (nil, nil)
// and the caller gracefully downgrades.
func (c *BillDotComAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *BillDotComAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":      ProviderName,
		"auth_type":     "session",
		"dev_key_short": shortToken(secrets.DevKey),
		"session_short": shortToken(secrets.SessionToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*BillDotComAccessConnector)(nil)
