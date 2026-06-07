// Package freshdesk implements the access.AccessConnector contract for the
// Freshdesk agents API.
package freshdesk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "freshdesk"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("freshdesk: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Domain string `json:"domain"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type FreshdeskAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *FreshdeskAccessConnector { return &FreshdeskAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("freshdesk: config is nil")
	}
	var cfg Config
	if v, ok := raw["domain"].(string); ok {
		cfg.Domain = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("freshdesk: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Domain) == "" {
		return errors.New("freshdesk: domain is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("freshdesk: api_key is required")
	}
	return nil
}

func (c *FreshdeskAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *FreshdeskAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://" + cfg.Domain + ".freshdesk.com"
}

func (c *FreshdeskAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func basicAuthHeader(apiKey string) string {
	creds := strings.TrimSpace(apiKey) + ":X"
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func (c *FreshdeskAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", basicAuthHeader(secrets.APIKey))
	return req, nil
}

func (c *FreshdeskAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", basicAuthHeader(secrets.APIKey))
	return req, nil
}

func (c *FreshdeskAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("freshdesk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *FreshdeskAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("freshdesk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("freshdesk: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *FreshdeskAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *FreshdeskAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/v2/agents/me"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("freshdesk: connect probe: %w", err)
	}
	return nil
}

func (c *FreshdeskAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type freshdeskAgent struct {
	ID        int64 `json:"id"`
	Available bool  `json:"available"`
	Active    *bool `json:"active,omitempty"`
	Contact   struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"contact"`
}

func (c *FreshdeskAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *FreshdeskAccessConnector) SyncIdentities(
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
		path := fmt.Sprintf("%s/api/v2/agents?per_page=%d&page=%d", base, pageSize, page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var agents []freshdeskAgent
		if err := json.Unmarshal(body, &agents); err != nil {
			return fmt.Errorf("freshdesk: decode agents: %w", err)
		}
		identities := make([]*access.Identity, 0, len(agents))
		for _, a := range agents {
			status := "active"
			if a.Active != nil && !*a.Active {
				status = "inactive"
			}
			display := a.Contact.Name
			if display == "" {
				display = a.Contact.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", a.ID),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       a.Contact.Email,
				Status:      status,
			})
		}
		next := ""
		// Freshdesk: a full page (== pageSize) means more results exist; a
		// short page is terminal.
		if len(agents) >= pageSize {
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

// ---------- advanced capabilities ----------

type freshdeskAgentDetail struct {
	ID       int64   `json:"id"`
	GroupIDs []int64 `json:"group_ids"`
}

func (c *FreshdeskAccessConnector) getAgent(ctx context.Context, cfg Config, secrets Secrets, agentID string) (*freshdeskAgentDetail, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL(cfg)+"/api/v2/agents/"+url.PathEscape(agentID))
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
		return nil, fmt.Errorf("freshdesk: agent GET status %d: %s", resp.StatusCode, string(body))
	}
	var agent freshdeskAgentDetail
	if err := json.Unmarshal(body, &agent); err != nil {
		return nil, fmt.Errorf("freshdesk: decode agent: %w", err)
	}
	return &agent, nil
}

func (c *FreshdeskAccessConnector) updateAgentGroups(ctx context.Context, cfg Config, secrets Secrets, agentID string, groupIDs []int64) error {
	payload := map[string]interface{}{"group_ids": groupIDs}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("freshdesk: marshal payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, c.baseURL(cfg)+"/api/v2/agents/"+url.PathEscape(agentID), body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("freshdesk: agent PUT status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ProvisionAccess adds the target group to an agent's group_ids via
// PUT /api/v2/agents/{agentId}. If the agent already has the group,
// PUT is still a no-op idempotent operation.
func (c *FreshdeskAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("freshdesk: grant.UserExternalID (agent id) is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("freshdesk: grant.ResourceExternalID (group id) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	groupID, err := strconv.ParseInt(grant.ResourceExternalID, 10, 64)
	if err != nil {
		return fmt.Errorf("freshdesk: group id must be numeric: %w", err)
	}
	agent, err := c.getAgent(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if agent == nil {
		return fmt.Errorf("freshdesk: agent %s not found", grant.UserExternalID)
	}
	for _, g := range agent.GroupIDs {
		if g == groupID {
			return nil
		}
	}
	agent.GroupIDs = append(agent.GroupIDs, groupID)
	return c.updateAgentGroups(ctx, cfg, secrets, grant.UserExternalID, agent.GroupIDs)
}

// RevokeAccess removes the target group from an agent's group_ids via
// PUT /api/v2/agents/{agentId}. Missing agent or missing group both map
// to idempotent success.
func (c *FreshdeskAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("freshdesk: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("freshdesk: grant.ResourceExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	groupID, err := strconv.ParseInt(grant.ResourceExternalID, 10, 64)
	if err != nil {
		return fmt.Errorf("freshdesk: group id must be numeric: %w", err)
	}
	agent, err := c.getAgent(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if agent == nil {
		return nil
	}
	found := false
	newGroups := make([]int64, 0, len(agent.GroupIDs))
	for _, g := range agent.GroupIDs {
		if g == groupID {
			found = true
			continue
		}
		newGroups = append(newGroups, g)
	}
	if !found {
		return nil
	}
	return c.updateAgentGroups(ctx, cfg, secrets, grant.UserExternalID, newGroups)
}

// ListEntitlements reads /api/v2/agents/{agentId} and emits one
// Entitlement per group_id.
func (c *FreshdeskAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("freshdesk: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	agent, err := c.getAgent(ctx, cfg, secrets, userExternalID)
	if err != nil {
		return nil, err
	}
	if agent == nil {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(agent.GroupIDs))
	for _, g := range agent.GroupIDs {
		out = append(out, access.Entitlement{
			ResourceExternalID: strconv.FormatInt(g, 10),
			Role:               "agent",
			Source:             "direct",
		})
	}
	return out, nil
}
func (c *FreshdeskAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *FreshdeskAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"domain":    cfg.Domain,
		"auth_type": "api_key",
		"key_short": shortToken(secrets.APIKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*FreshdeskAccessConnector)(nil)
