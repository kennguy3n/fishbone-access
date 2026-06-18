// Package quickbooks implements the access.AccessConnector contract for the
// QuickBooks Online Employees query API.
package quickbooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "quickbooks"
	pageSize     = 100

	// managedTitlePrefix tags the Employee.Title field so we never clear or
	// overwrite an HR-owned job title. QuickBooks Online has no real RBAC
	// surface for employees, so we co-opt Employee.Title as a single-slot
	// access role; the prefix scopes the field so only access-managed
	// values are touched by Provision / Revoke / ListEntitlements.
	managedTitlePrefix = "shieldnet-access:"
)

// realmIDPattern matches the numeric customer identifier QuickBooks
// Online stamps on every company file. Per Intuit's developer docs the
// realmID is a base-10 integer (typically 15-16 digits, no slashes,
// dots, or punctuation). Operators paste this value into the connector
// config, and `cfg.RealmID` is interpolated as a path segment in every
// `/v3/company/{realmID}/...` URL — including the new
// FetchAccessAuditLogs endpoint. We enforce the numeric shape at the
// validation boundary so a misconfigured or hostile RealmID can never
// inject extra path segments, query strings, or fragments (e.g.
// `"123/../admin"`, `"123?x=y"`, `"123#frag"`) into the URL.
var realmIDPattern = regexp.MustCompile(`^[0-9]{1,32}$`)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	RealmID string `json:"realm_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type QuickBooksAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *QuickBooksAccessConnector { return &QuickBooksAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("quickbooks: config is nil")
	}
	var cfg Config
	if v, ok := raw["realm_id"].(string); ok {
		cfg.RealmID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("quickbooks: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	realm := strings.TrimSpace(c.RealmID)
	if realm == "" {
		return errors.New("quickbooks: realm_id is required")
	}
	if !realmIDPattern.MatchString(realm) {
		return errors.New("quickbooks: realm_id must be a numeric Intuit company identifier (1-32 digits, no path separators)")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("quickbooks: access_token is required")
	}
	return nil
}

func (c *QuickBooksAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *QuickBooksAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://quickbooks.api.intuit.com"
}

func (c *QuickBooksAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *QuickBooksAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *QuickBooksAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("quickbooks: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("quickbooks: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *QuickBooksAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *QuickBooksAccessConnector) queryURL(cfg Config, query string) string {
	q := url.Values{}
	q.Set("query", query)
	q.Set("minorversion", "65")
	return fmt.Sprintf("%s/v3/company/%s/query?%s", c.baseURL(), cfg.RealmID, q.Encode())
}

func (c *QuickBooksAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.queryURL(cfg, "SELECT COUNT(*) FROM Employee")
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("quickbooks: connect probe: %w", err)
	}
	return nil
}

func (c *QuickBooksAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type qbEmployee struct {
	ID           string `json:"Id"`
	SyncToken    string `json:"SyncToken,omitempty"`
	GivenName    string `json:"GivenName"`
	FamilyName   string `json:"FamilyName"`
	DisplayName  string `json:"DisplayName"`
	Title        string `json:"Title,omitempty"`
	Active       bool   `json:"Active"`
	PrimaryEmail struct {
		Address string `json:"Address"`
	} `json:"PrimaryEmailAddr"`
}

type qbEmployeeEnvelope struct {
	Employee qbEmployee `json:"Employee"`
}

type qbQueryResponse struct {
	QueryResponse struct {
		Employee      []qbEmployee `json:"Employee"`
		StartPosition int          `json:"startPosition"`
		MaxResults    int          `json:"maxResults"`
		TotalCount    int          `json:"totalCount"`
	} `json:"QueryResponse"`
}

func (c *QuickBooksAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *QuickBooksAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	start := 1
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &start)
		if start < 1 {
			start = 1
		}
	}
	for {
		query := fmt.Sprintf("SELECT * FROM Employee STARTPOSITION %d MAXRESULTS %d", start, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, c.queryURL(cfg, query))
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp qbQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("quickbooks: decode query: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.QueryResponse.Employee))
		for _, e := range resp.QueryResponse.Employee {
			display := e.DisplayName
			if display == "" {
				display = strings.TrimSpace(e.GivenName + " " + e.FamilyName)
			}
			status := "active"
			if !e.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  e.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       e.PrimaryEmail.Address,
				Status:      status,
			})
		}
		next := ""
		if len(resp.QueryResponse.Employee) >= pageSize {
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
}

// ---------- advanced capabilities ----------

func (c *QuickBooksAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *QuickBooksAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("quickbooks: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *QuickBooksAccessConnector) getEmployee(ctx context.Context, cfg Config, secrets Secrets, employeeID string) (*qbEmployee, error) {
	fullURL := fmt.Sprintf("%s/v3/company/%s/employee/%s?minorversion=65", c.baseURL(), cfg.RealmID, url.PathEscape(employeeID))
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
		return nil, fmt.Errorf("quickbooks: employee GET status %d: %s", resp.StatusCode, string(body))
	}
	var envelope qbEmployeeEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("quickbooks: decode employee: %w", err)
	}
	return &envelope.Employee, nil
}

func (c *QuickBooksAccessConnector) sparseUpdateEmployee(ctx context.Context, cfg Config, secrets Secrets, emp qbEmployee) error {
	payload := map[string]interface{}{
		"Id":        emp.ID,
		"SyncToken": emp.SyncToken,
		"Title":     emp.Title,
		"sparse":    true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("quickbooks: marshal payload: %w", err)
	}
	fullURL := fmt.Sprintf("%s/v3/company/%s/employee?minorversion=65", c.baseURL(), cfg.RealmID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, fullURL, body)
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
		return fmt.Errorf("quickbooks: employee POST status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ProvisionAccess assigns a role to the employee via a sparse Employee
// update (Title field). QuickBooks Online has no employee-level RBAC
// API, so the connector co-opts Employee.Title as a single-slot role.
// To avoid trashing HR job-title data, the value is written with the
// managedTitlePrefix marker — Revoke and ListEntitlements only act on
// titles carrying this prefix, leaving non-managed titles untouched.
// If the employee already holds the role, no POST is issued
// (idempotent success).
func (c *QuickBooksAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("quickbooks: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("quickbooks: grant.ResourceExternalID (role) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	emp, err := c.getEmployee(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if emp == nil {
		return fmt.Errorf("quickbooks: employee %s not found", grant.UserExternalID)
	}
	desired := managedTitlePrefix + grant.ResourceExternalID
	if emp.Title == desired {
		return nil
	}
	// Refuse to overwrite an unmanaged Title (i.e., an HR-owned job
	// title). Operators must clear or migrate the field manually before
	// the access platform may take ownership.
	if emp.Title != "" && !strings.HasPrefix(emp.Title, managedTitlePrefix) {
		return fmt.Errorf("quickbooks: employee %s Title is HR-owned (%q); refusing to overwrite", grant.UserExternalID, emp.Title)
	}
	emp.Title = desired
	return c.sparseUpdateEmployee(ctx, cfg, secrets, *emp)
}

// RevokeAccess clears the employee's managed role via a sparse Employee
// update. Only Title values carrying the managedTitlePrefix marker are
// cleared — HR-owned titles are left untouched. Missing employee, role
// mismatch, or unmanaged title ⇒ idempotent success.
func (c *QuickBooksAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("quickbooks: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("quickbooks: grant.ResourceExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	emp, err := c.getEmployee(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if emp == nil {
		return nil
	}
	desired := managedTitlePrefix + grant.ResourceExternalID
	if emp.Title != desired {
		return nil
	}
	emp.Title = ""
	return c.sparseUpdateEmployee(ctx, cfg, secrets, *emp)
}

// ListEntitlements reads /v3/company/{realm}/employee/{id} and emits
// one Entitlement when the employee's Title carries the
// managedTitlePrefix marker (i.e., it was written by ProvisionAccess).
// Unmanaged HR job titles are deliberately ignored so they are never
// surfaced as access entitlements.
func (c *QuickBooksAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("quickbooks: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	emp, err := c.getEmployee(ctx, cfg, secrets, userExternalID)
	if err != nil {
		return nil, err
	}
	if emp == nil || !strings.HasPrefix(emp.Title, managedTitlePrefix) {
		return nil, nil
	}
	role := strings.TrimPrefix(emp.Title, managedTitlePrefix)
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker QuickBooks
// Online (Intuit Identity) SAML 2.0 SP federation. When `sso_metadata_url`
// is blank the helper returns (nil, nil) and the caller gracefully
// downgrades.
func (c *QuickBooksAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *QuickBooksAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"realm_id":    cfg.RealmID,
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

var _ access.AccessConnector = (*QuickBooksAccessConnector)(nil)
