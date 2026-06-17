// Package salesforce implements the access.AccessConnector contract for the
// Salesforce REST/SOQL users API.
package salesforce

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

	"bytes"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName       = "salesforce"
	defaultAPIVersion  = "v59.0"
	soqlListUsersQuery = "SELECT Id, Name, Email, IsActive FROM User"
)

// escapeSOQLLiteral escapes a value for safe interpolation inside a SOQL
// single-quoted string literal. Salesforce SOQL requires each embedded single
// quote to be backslash-escaped and each backslash to be doubled; URL
// encoding alone (`url.QueryEscape`) does NOT protect against injection here
// because Salesforce URL-decodes the `q=` query parameter before the SOQL
// parser sees it, so `%27` decodes back to `'` and an attacker-controlled
// external ID can still break out of the string literal.
func escapeSOQLLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	InstanceURL string `json:"instance_url"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type SalesforceAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SalesforceAccessConnector { return &SalesforceAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("salesforce: config is nil")
	}
	var cfg Config
	if v, ok := raw["instance_url"].(string); ok {
		cfg.InstanceURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("salesforce: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	u := strings.TrimSpace(c.InstanceURL)
	if u == "" {
		return errors.New("salesforce: instance_url is required")
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return errors.New("salesforce: instance_url must include scheme (https://)")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("salesforce: access_token is required")
	}
	return nil
}

func (c *SalesforceAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

// instanceBase returns the configured instance URL — or, when the test
// harness has set urlOverride, the test server URL. This lets all REST
// endpoints (login probe, query, queryMore) be redirected through the
// same fake.
func (c *SalesforceAccessConnector) instanceBase(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(cfg.InstanceURL, "/")
}

func (c *SalesforceAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SalesforceAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *SalesforceAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("salesforce: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("salesforce: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *SalesforceAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SalesforceAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.instanceBase(cfg) + "/services/data/" + defaultAPIVersion + "/sobjects/User/describe"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("salesforce: connect probe: %w", err)
	}
	return nil
}

func (c *SalesforceAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type sfQueryResponse struct {
	TotalSize      int         `json:"totalSize"`
	Done           bool        `json:"done"`
	NextRecordsURL string      `json:"nextRecordsUrl,omitempty"`
	Records        []sfUserRow `json:"records"`
}

type sfUserRow struct {
	ID       string `json:"Id"`
	Name     string `json:"Name"`
	Email    string `json:"Email"`
	IsActive bool   `json:"IsActive"`
}

func (c *SalesforceAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SalesforceAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	base := c.instanceBase(cfg)
	var nextURL string
	if checkpoint != "" {
		nextURL = base + checkpoint
	} else {
		q := url.Values{"q": {soqlListUsersQuery}}
		nextURL = base + "/services/data/" + defaultAPIVersion + "/query?" + q.Encode()
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp sfQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("salesforce: decode soql: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Records))
		for _, u := range resp.Records {
			status := "active"
			if !u.IsActive {
				status = "inactive"
			}
			display := u.Name
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := resp.NextRecordsURL
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" || resp.Done {
			return nil
		}
		nextURL = base + next
	}
}

func (c *SalesforceAccessConnector) ProvisionAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("salesforce: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"AssigneeId": grant.UserExternalID, "PermissionSetId": grant.ResourceExternalID})
	urlStr := c.instanceURL(configRaw) + "/services/data/v59.0/sobjects/PermissionSetAssignment"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("salesforce: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if strings.Contains(string(respBody), "DUPLICATE_VALUE") {
		return nil
	}
	return fmt.Errorf("salesforce: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *SalesforceAccessConnector) RevokeAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("salesforce: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("SELECT+Id+FROM+PermissionSetAssignment+WHERE+AssigneeId='%s'+AND+PermissionSetId='%s'",
		url.QueryEscape(escapeSOQLLiteral(grant.UserExternalID)), url.QueryEscape(escapeSOQLLiteral(grant.ResourceExternalID)))
	queryURL := c.instanceURL(configRaw) + "/services/data/v59.0/query?q=" + query
	req, err := c.newRequest(ctx, secrets, http.MethodGet, queryURL)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return fmt.Errorf("salesforce: revoke query: %w", err)
	}
	var result struct {
		Records []struct {
			ID string `json:"Id"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("salesforce: decode revoke query: %w", err)
	}
	if len(result.Records) == 0 {
		return nil
	}
	delURL := c.instanceURL(configRaw) + "/services/data/v59.0/sobjects/PermissionSetAssignment/" + result.Records[0].ID
	delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, delURL, nil)
	if err != nil {
		return err
	}
	delReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(delReq)
	if err != nil {
		return fmt.Errorf("salesforce: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("salesforce: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *SalesforceAccessConnector) ListEntitlements(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("salesforce: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("SELECT+PermissionSet.Name,PermissionSetId+FROM+PermissionSetAssignment+WHERE+AssigneeId='%s'",
		url.QueryEscape(escapeSOQLLiteral(userExternalID)))
	queryURL := c.instanceURL(configRaw) + "/services/data/v59.0/query?q=" + query
	req, err := c.newRequest(ctx, secrets, http.MethodGet, queryURL)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var result struct {
		Records []struct {
			PermissionSet struct {
				Name string `json:"Name"`
			} `json:"PermissionSet"`
			PermissionSetID string `json:"PermissionSetId"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("salesforce: decode: %w", err)
	}
	var out []access.Entitlement
	for _, r := range result.Records {
		out = append(out, access.Entitlement{
			ResourceExternalID: r.PermissionSetID,
			Role:               r.PermissionSet.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

// GetSSOMetadata returns the Salesforce SAML metadata URL for the configured
// instance. Salesforce orgs publish their SAML metadata at
// `/identity/saml/metadata` under the org's instance URL once SSO is enabled
// — this method composes the URL deterministically without issuing any HTTP
// request, mirroring the GitHub / Jira / Zendesk pattern.
func (c *SalesforceAccessConnector) instanceURL(configRaw map[string]interface{}) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	cfg, _ := DecodeConfig(configRaw)
	if cfg.InstanceURL != "" {
		return strings.TrimRight(cfg.InstanceURL, "/")
	}
	return "https://login.salesforce.com"
}

func (c *SalesforceAccessConnector) GetSSOMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(cfg.InstanceURL, "/")
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: base + "/identity/saml/metadata",
		EntityID:    base,
	}, nil
}

func (c *SalesforceAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":     ProviderName,
		"instance_url": cfg.InstanceURL,
		"auth_type":    "access_token",
		"token_short":  shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*SalesforceAccessConnector)(nil)
