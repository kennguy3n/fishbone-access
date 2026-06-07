// Package sumo_logic implements the access.AccessConnector contract for the
// Sumo Logic /api/v1/users API.
package sumo_logic

import (
	"context"
	"encoding/base64"
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
	ProviderName = "sumo_logic"
	pageSize     = 100
	// sumoIdentitiesMaxPages caps SyncIdentities pagination as a
	// defense-in-depth guard against an upstream that never returns a
	// short final page. Mirrors splunkIdentitiesMaxPages in
	// splunk/connector.go.
	sumoIdentitiesMaxPages = 2000
)

var ErrNotImplemented = fmt.Errorf("sumo_logic: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// Deployment selects the Sumo Logic deployment region (e.g. "us1",
	// "us2", "eu", "au"). Empty string defaults to "us2".
	Deployment string `json:"deployment"`
}

type Secrets struct {
	AccessID  string `json:"access_id"`
	AccessKey string `json:"access_key"`
}

type SumoLogicAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SumoLogicAccessConnector { return &SumoLogicAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("sumo_logic: config is nil")
	}
	var cfg Config
	if v, ok := raw["deployment"].(string); ok {
		cfg.Deployment = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("sumo_logic: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_id"].(string); ok {
		s.AccessID = v
	}
	if v, ok := raw["access_key"].(string); ok {
		s.AccessKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	dep := strings.TrimSpace(c.Deployment)
	if dep == "" {
		return nil
	}
	if !isDNSLabel(dep) {
		return errors.New("sumo_logic: deployment must be a single DNS label (e.g. us1, us2, eu, au)")
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
	if strings.TrimSpace(s.AccessID) == "" {
		return errors.New("sumo_logic: access_id is required")
	}
	if strings.TrimSpace(s.AccessKey) == "" {
		return errors.New("sumo_logic: access_key is required")
	}
	return nil
}

func (c *SumoLogicAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SumoLogicAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	dep := strings.TrimSpace(cfg.Deployment)
	if dep == "" {
		dep = "us2"
	}
	if strings.EqualFold(dep, "us1") {
		return "https://api.sumologic.com"
	}
	return "https://api." + strings.ToLower(dep) + ".sumologic.com"
}

func (c *SumoLogicAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SumoLogicAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Sumo-Client", "shieldnet360-access")
	creds := strings.TrimSpace(secrets.AccessID) + ":" + strings.TrimSpace(secrets.AccessKey)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *SumoLogicAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sumo_logic: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sumo_logic: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, httputil.SafeErrorBody(body))
	}
	return body, nil
}

func (c *SumoLogicAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SumoLogicAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/api/v1/users?limit=1&offset=0", c.baseURL(cfg))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("sumo_logic: connect probe: %w", err)
	}
	return nil
}

func (c *SumoLogicAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type sumoUser struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	IsActive  bool   `json:"isActive"`
	IsLocked  bool   `json:"isLocked"`
}

type sumoListResponse struct {
	Data []sumoUser `json:"data"`
	Next string     `json:"next"`
}

func (c *SumoLogicAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SumoLogicAccessConnector) SyncIdentities(
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
	for pages := 0; pages < sumoIdentitiesMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/api/v1/users?limit=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp sumoListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("sumo_logic: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
			display := strings.TrimSpace(u.FirstName + " " + u.LastName)
			if display == "" {
				display = u.Email
			}
			status := "active"
			if u.IsLocked {
				status = "locked"
			} else if !u.IsActive {
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
		if len(resp.Data) == pageSize {
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
	return fmt.Errorf("sumo_logic: sync identities: pagination exceeded %d pages", sumoIdentitiesMaxPages)
}

func (c *SumoLogicAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SumoLogicAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"auth_type": "basic",
		"id_short":  shortToken(secrets.AccessID),
		"key_short": shortToken(secrets.AccessKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*SumoLogicAccessConnector)(nil)
