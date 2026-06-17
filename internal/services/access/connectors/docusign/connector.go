// Package docusign implements the access.AccessConnector contract for the
// DocuSign /restapi/v2.1/users API.
package docusign

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
	ProviderName = "docusign"
	pageSize     = 100
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	AccountEnvironment string `json:"account_environment"`
	// AccountID is the DocuSign API account GUID. Every eSignature
	// REST call is account-scoped (/restapi/v2.1/accounts/{accountId}/...),
	// so this is required for all user/group operations.
	AccountID string `json:"account_id"`
}

type Secrets struct {
	Token string `json:"token"`
}

type DocuSignAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DocuSignAccessConnector { return &DocuSignAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

var allowedEnvs = map[string]struct{}{
	"production": {},
	"demo":       {},
}

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("docusign: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_environment"].(string); ok {
		cfg.AccountEnvironment = v
	}
	if v, ok := raw["account_id"].(string); ok {
		cfg.AccountID = strings.TrimSpace(v)
	}
	if strings.TrimSpace(cfg.AccountEnvironment) == "" {
		cfg.AccountEnvironment = "production"
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("docusign: secrets is nil")
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
		return fmt.Errorf("docusign: account_environment must be one of production|demo, got %q", c.AccountEnvironment)
	}
	return nil
}

// requireAccountID guards the account-scoped eSignature user/group
// endpoints. account_id is not required for SCIM provisioning (which is
// keyed by scim_base_url/scim_token), so it is enforced here per-call
// rather than in the shared Config.validate().
func (c Config) requireAccountID() error {
	if strings.TrimSpace(c.AccountID) == "" {
		return errors.New("docusign: account_id is required for user/group operations")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("docusign: token is required")
	}
	return nil
}

func (c *DocuSignAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DocuSignAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if strings.ToLower(strings.TrimSpace(cfg.AccountEnvironment)) == "demo" {
		return "https://demo.docusign.net"
	}
	return "https://www.docusign.net"
}

// usersBaseURL returns the account-scoped eSignature REST base, e.g.
// https://www.docusign.net/restapi/v2.1/accounts/{accountId}. DocuSign
// requires the {accountId} segment on every user/group endpoint; omitting
// it returns 404 against the real API.
func (c *DocuSignAccessConnector) usersBaseURL(cfg Config) string {
	return c.baseURL(cfg) + "/restapi/v2.1/accounts/" + url.PathEscape(cfg.AccountID)
}

func (c *DocuSignAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DocuSignAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *DocuSignAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *DocuSignAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("docusign: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *DocuSignAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("docusign: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docusign: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *DocuSignAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *DocuSignAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if err := cfg.requireAccountID(); err != nil {
		return err
	}
	q := url.Values{"page": []string{"1"}, "per_page": []string{"1"}}
	probe := c.usersBaseURL(cfg) + "/users?" + q.Encode()
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("docusign: connect probe: %w", err)
	}
	return nil
}

func (c *DocuSignAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type docusignUser struct {
	ID        string `json:"userId"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Status    bool   `json:"active"`
}

type docusignListResponse struct {
	Items []docusignUser `json:"users"`
}

func (c *DocuSignAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *DocuSignAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if err := cfg.requireAccountID(); err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 1 {
			page = 1
		}
	}
	base := c.usersBaseURL(cfg)
	for {
		q := url.Values{
			"page":     []string{fmt.Sprintf("%d", page)},
			"per_page": []string{fmt.Sprintf("%d", pageSize)},
		}
		path := base + "/users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp docusignListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("docusign: decode users: %w", err)
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

// ---------- advanced capabilities ----------

type docusignGroupRef struct {
	GroupID   string `json:"groupId"`
	GroupName string `json:"groupName,omitempty"`
	GroupType string `json:"groupType,omitempty"`
}

type docusignGroupsResponse struct {
	Groups        []docusignGroupRef `json:"groups"`
	ResultSetSize string             `json:"resultSetSize,omitempty"`
	StartPosition string             `json:"startPosition,omitempty"`
	TotalSetSize  string             `json:"totalSetSize,omitempty"`
}

// ProvisionAccess adds a user to a group via
// PUT /restapi/v2.1/users/{userId}/groups with groups array.
// 409 / "already in group" maps to idempotent success.
func (c *DocuSignAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("docusign: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("docusign: grant.ResourceExternalID (groupId) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if err := cfg.requireAccountID(); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"groups": []map[string]interface{}{{"groupId": grant.ResourceExternalID}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("docusign: marshal payload: %w", err)
	}
	fullURL := c.usersBaseURL(cfg) + "/users/" + url.PathEscape(grant.UserExternalID) + "/groups"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, fullURL, body)
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
		return fmt.Errorf("docusign: group PUT status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a group via
// DELETE /restapi/v2.1/users/{userId}/groups. 404 ⇒ idempotent success.
func (c *DocuSignAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("docusign: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("docusign: grant.ResourceExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if err := cfg.requireAccountID(); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"groups": []map[string]interface{}{{"groupId": grant.ResourceExternalID}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("docusign: marshal payload: %w", err)
	}
	fullURL := c.usersBaseURL(cfg) + "/users/" + url.PathEscape(grant.UserExternalID) + "/groups"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, fullURL, body)
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
	default:
		return fmt.Errorf("docusign: group DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements reads /restapi/v2.1/users/{userId}/groups and emits
// one Entitlement per group membership.
func (c *DocuSignAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("docusign: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.requireAccountID(); err != nil {
		return nil, err
	}
	fullURL := c.usersBaseURL(cfg) + "/users/" + url.PathEscape(userExternalID) + "/groups"
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
		return nil, fmt.Errorf("docusign: groups GET status %d: %s", resp.StatusCode, string(body))
	}
	var data docusignGroupsResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("docusign: decode groups: %w", err)
	}
	out := make([]access.Entitlement, 0, len(data.Groups))
	for _, g := range data.Groups {
		out = append(out, access.Entitlement{
			ResourceExternalID: g.GroupID,
			Role:               g.GroupName,
			Source:             "direct",
		})
	}
	return out, nil
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// DocuSign account. DocuSign supports SAML 2.0 SSO via the DocuSign
// Trust admin console; the connector forwards the operator-supplied
// URLs verbatim via access.SSOMetadataFromConfig so the
// SSOFederationService can register a iam-core SAML broker. Returns
// (nil, nil) when the operator has not supplied a metadata URL so
// the caller gracefully downgrades.
func (c *DocuSignAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DocuSignAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*DocuSignAccessConnector)(nil)
