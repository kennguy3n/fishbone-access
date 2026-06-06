// Package netsuite implements the access.AccessConnector contract for NetSuite SuiteTalk REST /record/v1/employee with bearer auth + offset/limit pagination.
package netsuite

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
	ProviderName = "netsuite"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("netsuite: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type NetSuiteAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *NetSuiteAccessConnector { return &NetSuiteAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("netsuite: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("netsuite: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("netsuite: token is required")
	}
	return nil
}

func (c *NetSuiteAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *NetSuiteAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.netsuite.com"
}

func (c *NetSuiteAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *NetSuiteAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *NetSuiteAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *NetSuiteAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("netsuite: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *NetSuiteAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("netsuite: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("netsuite: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *NetSuiteAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *NetSuiteAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_ = cfg
	probe := c.baseURL() + ("/record/v1/employee") + "?offset=0&limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("netsuite: connect probe: %w", err)
	}
	return nil
}

func (c *NetSuiteAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type netsuiteUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"entityId"`
}

type netsuiteListResponse struct {
	Items []netsuiteUser `json:"items"`
}

func (c *NetSuiteAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *NetSuiteAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_ = cfg
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	base := c.baseURL()
	path := base + ("/record/v1/employee")
	for {
		q := url.Values{
			"offset": []string{fmt.Sprintf("%d", offset)},
			"limit":  []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := path + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp netsuiteListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("netsuite: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Items))
		for _, u := range resp.Items {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if len(resp.Items) == pageSize {
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

type netsuiteRoleRef struct {
	ID      string `json:"id"`
	RefName string `json:"refName,omitempty"`
}

type netsuiteRolesEnvelope struct {
	Items []netsuiteRoleRef `json:"items"`
}

type netsuiteEmployeeDetail struct {
	ID    string                `json:"id"`
	Roles netsuiteRolesEnvelope `json:"roles"`
}

func (c *NetSuiteAccessConnector) getEmployee(ctx context.Context, secrets Secrets, employeeID string) (*netsuiteEmployeeDetail, error) {
	fullURL := c.baseURL() + "/record/v1/employee/" + url.PathEscape(employeeID) + "?expandSubResources=true"
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
		return nil, fmt.Errorf("netsuite: employee GET status %d: %s", resp.StatusCode, string(body))
	}
	var emp netsuiteEmployeeDetail
	if err := json.Unmarshal(body, &emp); err != nil {
		return nil, fmt.Errorf("netsuite: decode employee: %w", err)
	}
	return &emp, nil
}

func (c *NetSuiteAccessConnector) patchEmployeeRoles(ctx context.Context, secrets Secrets, employeeID string, roles []netsuiteRoleRef) error {
	payload := map[string]interface{}{
		"roles": map[string]interface{}{"items": roles},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("netsuite: marshal payload: %w", err)
	}
	fullURL := c.baseURL() + "/record/v1/employee/" + url.PathEscape(employeeID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPatch, fullURL, body)
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
		return fmt.Errorf("netsuite: employee PATCH status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ProvisionAccess adds a role to the employee via
// PATCH /record/v1/employee/{id} with the full roles list. If the role
// is already present, no PATCH is issued (idempotent success).
func (c *NetSuiteAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("netsuite: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("netsuite: grant.ResourceExternalID (role id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	emp, err := c.getEmployee(ctx, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if emp == nil {
		return fmt.Errorf("netsuite: employee %s not found", grant.UserExternalID)
	}
	for _, r := range emp.Roles.Items {
		if r.ID == grant.ResourceExternalID {
			return nil
		}
	}
	// Build the roles slice by explicit copy rather than append to
	// avoid mutating the underlying array of emp.Roles.Items. Today
	// getEmployee returns a freshly-decoded slice with no spare
	// capacity, but an explicit copy makes the contract independent
	// of that detail (e.g. a future refactor that reuses a buffer).
	roles := make([]netsuiteRoleRef, len(emp.Roles.Items), len(emp.Roles.Items)+1)
	copy(roles, emp.Roles.Items)
	roles = append(roles, netsuiteRoleRef{ID: grant.ResourceExternalID})
	return c.patchEmployeeRoles(ctx, secrets, grant.UserExternalID, roles)
}

// RevokeAccess removes a role from the employee via
// PATCH /record/v1/employee/{id}. Missing employee or missing role both
// map to idempotent success.
func (c *NetSuiteAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("netsuite: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("netsuite: grant.ResourceExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	emp, err := c.getEmployee(ctx, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if emp == nil {
		return nil
	}
	found := false
	roles := make([]netsuiteRoleRef, 0, len(emp.Roles.Items))
	for _, r := range emp.Roles.Items {
		if r.ID == grant.ResourceExternalID {
			found = true
			continue
		}
		roles = append(roles, r)
	}
	if !found {
		return nil
	}
	return c.patchEmployeeRoles(ctx, secrets, grant.UserExternalID, roles)
}

// ListEntitlements reads /record/v1/employee/{id}?expandSubResources=true
// and emits one Entitlement per role assignment.
func (c *NetSuiteAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("netsuite: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	emp, err := c.getEmployee(ctx, secrets, userExternalID)
	if err != nil {
		return nil, err
	}
	if emp == nil {
		return nil, nil
	}
	out := make([]access.Entitlement, 0, len(emp.Roles.Items))
	for _, r := range emp.Roles.Items {
		out = append(out, access.Entitlement{
			ResourceExternalID: r.ID,
			Role:               r.RefName,
			Source:             "direct",
		})
	}
	return out, nil
}
func (c *NetSuiteAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *NetSuiteAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*NetSuiteAccessConnector)(nil)
