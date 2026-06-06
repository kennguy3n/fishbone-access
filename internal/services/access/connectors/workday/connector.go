// Package workday implements the access.AccessConnector contract for the
// Workday workers REST API.
package workday

import (
	"bytes"
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
	ProviderName = "workday"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("workday: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Host   string `json:"host"`
	Tenant string `json:"tenant"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type WorkdayAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *WorkdayAccessConnector { return &WorkdayAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("workday: config is nil")
	}
	var cfg Config
	if v, ok := raw["host"].(string); ok {
		cfg.Host = v
	}
	if v, ok := raw["tenant"].(string); ok {
		cfg.Tenant = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("workday: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("workday: host is required (e.g. wd5-impl-services1.workday.com)")
	}
	if strings.TrimSpace(c.Tenant) == "" {
		return errors.New("workday: tenant is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("workday: access_token is required")
	}
	return nil
}

func (c *WorkdayAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *WorkdayAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + strings.TrimSpace(cfg.Host)
}

func (c *WorkdayAccessConnector) ssoBaseURL(cfg Config) string {
	return "https://" + strings.TrimSpace(cfg.Host)
}

func (c *WorkdayAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *WorkdayAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *WorkdayAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *WorkdayAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("workday: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *WorkdayAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("workday: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("workday: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *WorkdayAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *WorkdayAccessConnector) workersURL(cfg Config) string {
	return fmt.Sprintf("%s/ccx/api/v1/%s/workers", c.baseURL(cfg), cfg.Tenant)
}

func (c *WorkdayAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.workersURL(cfg) + "?limit=1&offset=0"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("workday: connect probe: %w", err)
	}
	return nil
}

func (c *WorkdayAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type workdayWorker struct {
	ID           string `json:"id"`
	WorkerID     string `json:"workerId"`
	Descriptor   string `json:"descriptor"`
	Active       bool   `json:"active"`
	PrimaryEmail string `json:"primaryEmail"`
}

type workdayResponse struct {
	Total int             `json:"total"`
	Data  []workdayWorker `json:"data"`
}

func (c *WorkdayAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *WorkdayAccessConnector) SyncIdentities(
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
	for {
		path := fmt.Sprintf("%s?limit=%d&offset=%d", c.workersURL(cfg), pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp workdayResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("workday: decode workers: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, w := range resp.Data {
			id := w.ID
			if id == "" {
				id = w.WorkerID
			}
			status := "active"
			if !w.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  id,
				Type:        access.IdentityTypeUser,
				DisplayName: w.Descriptor,
				Email:       w.PrimaryEmail,
				Status:      status,
			})
		}
		next := ""
		if offset+len(resp.Data) < resp.Total && len(resp.Data) > 0 {
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
}

// ---------- advanced capabilities ----------

type workdayRoleRef struct {
	ID         string `json:"id"`
	Descriptor string `json:"descriptor,omitempty"`
}

type workdayWorkerDetail struct {
	ID    string           `json:"id"`
	Roles []workdayRoleRef `json:"securityRoles,omitempty"`
}

func (c *WorkdayAccessConnector) commonURL(cfg Config, suffix string) string {
	return fmt.Sprintf("%s/ccx/api/v1/%s/%s", c.baseURL(cfg), cfg.Tenant, suffix)
}

// ProvisionAccess assigns an organization role/security group via
// POST /ccx/api/v1/{tenant}/assignOrganizationRoles. 409 / "already assigned"
// map to idempotent success.
func (c *WorkdayAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("workday: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("workday: grant.ResourceExternalID (role id) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"worker": map[string]interface{}{"id": grant.UserExternalID},
		"role":   map[string]interface{}{"id": grant.ResourceExternalID},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("workday: marshal payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.commonURL(cfg, "assignOrganizationRoles"), body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("already")):
		return nil
	default:
		return fmt.Errorf("workday: assign POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes an organization role via
// POST /ccx/api/v1/{tenant}/unassignOrganizationRoles. 404 / "not assigned"
// map to idempotent success.
func (c *WorkdayAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("workday: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("workday: grant.ResourceExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"worker": map[string]interface{}{"id": grant.UserExternalID},
		"role":   map[string]interface{}{"id": grant.ResourceExternalID},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("workday: marshal payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.commonURL(cfg, "unassignOrganizationRoles"), body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return nil
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("not assigned")):
		return nil
	default:
		return fmt.Errorf("workday: unassign POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements reads /ccx/api/v1/{tenant}/workers/{workerId} with
// expand=securityRoles and emits one Entitlement per role assignment.
func (c *WorkdayAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("workday: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	fullURL := c.workersURL(cfg) + "/" + url.PathEscape(userExternalID) + "?expand=securityRoles"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("workday: worker GET status %d: %s", resp.StatusCode, string(body))
	}
	var worker workdayWorkerDetail
	if err := json.Unmarshal(body, &worker); err != nil {
		return nil, fmt.Errorf("workday: decode worker: %w", err)
	}
	out := make([]access.Entitlement, 0, len(worker.Roles))
	for _, role := range worker.Roles {
		out = append(out, access.Entitlement{
			ResourceExternalID: role.ID,
			Role:               role.Descriptor,
			Source:             "direct",
		})
	}
	return out, nil
}

func (c *WorkdayAccessConnector) GetSSOMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	host := c.ssoBaseURL(cfg)
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: fmt.Sprintf("%s/%s/saml2/metadata", host, cfg.Tenant),
		EntityID:    fmt.Sprintf("%s/%s", host, cfg.Tenant),
	}, nil
}

func (c *WorkdayAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"host":        cfg.Host,
		"tenant":      cfg.Tenant,
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

var _ access.AccessConnector = (*WorkdayAccessConnector)(nil)
