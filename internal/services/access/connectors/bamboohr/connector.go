// Package bamboohr implements the access.AccessConnector contract for the
// BambooHR employee directory API.
package bamboohr

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
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ProviderName = "bamboohr"

var ErrNotImplemented = fmt.Errorf("bamboohr: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Subdomain string `json:"subdomain"`
}

type Secrets struct {
	APIKey string `json:"api_key"`
}

type BambooHRAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *BambooHRAccessConnector { return &BambooHRAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("bamboohr: config is nil")
	}
	var cfg Config
	if v, ok := raw["subdomain"].(string); ok {
		cfg.Subdomain = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("bamboohr: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Subdomain) == "" {
		return errors.New("bamboohr: subdomain is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("bamboohr: api_key is required")
	}
	return nil
}

func (c *BambooHRAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *BambooHRAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.bamboohr.com/api/gateway.php/" + cfg.Subdomain
}

func (c *BambooHRAccessConnector) ssoBaseURL(cfg Config) string {
	return "https://" + cfg.Subdomain + ".bamboohr.com"
}

func (c *BambooHRAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *BambooHRAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	creds := strings.TrimSpace(secrets.APIKey) + ":x"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *BambooHRAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("bamboohr: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &httpStatusError{
			Method:     req.Method,
			Path:       req.URL.Path,
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}
	return body, nil
}

// httpStatusError is returned by do() whenever the upstream returns
// a non-2xx response. Callers branch on StatusCode (via errors.As)
// to distinguish auth (401), tier gating (403), bad cursor (400)
// from transient failures. Avoids fragile string-match on Error().
type httpStatusError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("bamboohr: %s %s: status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

func (c *BambooHRAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *BambooHRAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/v1/meta/users"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("bamboohr: connect probe: %w", err)
	}
	return nil
}

func (c *BambooHRAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type bambooEmployee struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	WorkEmail   string `json:"workEmail"`
	JobTitle    string `json:"jobTitle"`
	Status      string `json:"status"`
}

type bambooDirectoryResponse struct {
	Employees []bambooEmployee `json:"employees"`
}

func (c *BambooHRAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *BambooHRAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := c.baseURL(cfg) + "/v1/employees/directory"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp bambooDirectoryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("bamboohr: decode directory: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Employees))
	for i := range resp.Employees {
		identities = append(identities, identityFromBambooEmployee(&resp.Employees[i]))
	}
	return handler(identities, "")
}

// identityFromBambooEmployee converts a BambooHR employee record
// into the canonical access.Identity shape. Centralised here so the
// full-sync (SyncIdentities) and delta-sync (SyncIdentitiesDelta)
// paths emit identical records for the same employee — a downstream
// reconciler comparing the two snapshots must never see a field
// disagree just because one path took a different code branch.
//
// Field derivation rules:
//
//   - DisplayName: prefer the explicit displayName field, fall back
//     to "firstName lastName", final fallback to workEmail so the
//     emitted record always has *something* in the human-readable
//     slot.
//   - Status: BambooHR uses sentence-case "Active" / "Inactive";
//     normalised to lowercase. Empty status is treated as "active"
//     (matches BambooHR's behaviour where the field is sometimes
//     omitted for currently-employed records).
func identityFromBambooEmployee(e *bambooEmployee) *access.Identity {
	display := e.DisplayName
	if display == "" {
		display = strings.TrimSpace(e.FirstName + " " + e.LastName)
	}
	if display == "" {
		display = e.WorkEmail
	}
	status := "active"
	if e.Status != "" && !strings.EqualFold(e.Status, "active") {
		status = strings.ToLower(e.Status)
	}
	return &access.Identity{
		ExternalID:  e.ID,
		Type:        access.IdentityTypeUser,
		DisplayName: display,
		Email:       e.WorkEmail,
		Status:      status,
		RawData:     map[string]interface{}{"job_title": e.JobTitle},
	}
}

// ---------- advanced capabilities ----------

// bambooAccessLevelRow is a row in the BambooHR customAccessLevels
// table. BambooHR's employee custom-table API returns rows with a
// numeric `id` plus a `value` (the access level name). We use those
// two columns as ResourceExternalID and Role respectively so the
// downstream RBAC code can resolve "which BambooHR access level does
// this user have" without round-tripping to the directory.
type bambooAccessLevelRow struct {
	ID    json.Number `json:"id"`
	Value string      `json:"value"`
}

// doRaw returns the *http.Response so callers can branch on the
// status code (e.g. treat 404 on DELETE as idempotent). Callers MUST
// close the body.
func (c *BambooHRAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	return c.client().Do(req)
}

// newRequestWithJSON is identical to newRequest but writes a JSON
// payload on the wire and sets Content-Type. body may be nil.
func (c *BambooHRAccessConnector) newRequestWithJSON(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	creds := strings.TrimSpace(secrets.APIKey) + ":x"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

// findAccessLevelRowID returns the row id of the customAccessLevels
// row whose `value` matches the requested access level (Role). A
// missing row yields ("", nil) — callers treat this as idempotent
// success for revoke.
func (c *BambooHRAccessConnector) findAccessLevelRowID(ctx context.Context, cfg Config, secrets Secrets, employeeID, role string) (string, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		return "", nil
	}
	urlStr := c.baseURL(cfg) + "/v1/employees/" + url.PathEscape(employeeID) + "/tables/customAccessLevels"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return "", fmt.Errorf("bamboohr: GET customAccessLevels: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("bamboohr: customAccessLevels GET status %d: %s", resp.StatusCode, string(body))
	}
	var rows []bambooAccessLevelRow
	if err := json.Unmarshal(body, &rows); err != nil {
		// BambooHR may wrap rows in an envelope; try the {"customAccessLevels":[...]} shape too.
		var envelope struct {
			CustomAccessLevels []bambooAccessLevelRow `json:"customAccessLevels"`
		}
		if e2 := json.Unmarshal(body, &envelope); e2 != nil {
			return "", fmt.Errorf("bamboohr: decode customAccessLevels: %w", err)
		}
		rows = envelope.CustomAccessLevels
	}
	for _, r := range rows {
		if strings.EqualFold(r.Value, role) {
			return r.ID.String(), nil
		}
	}
	return "", nil
}

// ProvisionAccess sets a BambooHR custom-access-level row on an
// employee. The implementation uses POST + JSON body to create a new
// row in /v1/employees/{employeeID}/tables/customAccessLevels with
// `value` = grant.Role. Idempotency: a 409 Conflict response (or a
// 400 whose body mentions "already") is treated as success.
//
// grant.UserExternalID is the BambooHR employee ID.
// grant.ResourceExternalID is informational only — the access level
// itself is encoded in grant.Role.
func (c *BambooHRAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("bamboohr: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.Role) == "" {
		return errors.New("bamboohr: grant.Role is required (access level name)")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]string{"value": grant.Role}
	body, _ := json.Marshal(payload)
	urlStr := c.baseURL(cfg) + "/v1/employees/" + url.PathEscape(grant.UserExternalID) + "/tables/customAccessLevels"
	req, err := c.newRequestWithJSON(ctx, secrets, http.MethodPost, urlStr, body)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("bamboohr: provision request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("already")):
		return nil
	default:
		return fmt.Errorf("bamboohr: provision status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess deletes the access-level row for the user. 404 on the
// lookup or the DELETE is treated as idempotent success.
func (c *BambooHRAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("bamboohr: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.Role) == "" {
		return errors.New("bamboohr: grant.Role is required (access level name)")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	rowID, err := c.findAccessLevelRowID(ctx, cfg, secrets, grant.UserExternalID, grant.Role)
	if err != nil {
		return err
	}
	if rowID == "" {
		return nil
	}
	urlStr := c.baseURL(cfg) + "/v1/employees/" + url.PathEscape(grant.UserExternalID) +
		"/tables/customAccessLevels/" + url.PathEscape(rowID)
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, urlStr)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("bamboohr: revoke request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("bamboohr: revoke status %d: %s", resp.StatusCode, string(body))
	}
}

// ListEntitlements returns all customAccessLevels rows for the
// employee. Each row becomes one Entitlement{ResourceExternalID: id,
// Role: value, Source: "direct"}.
func (c *BambooHRAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if strings.TrimSpace(userExternalID) == "" {
		return nil, errors.New("bamboohr: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	urlStr := c.baseURL(cfg) + "/v1/employees/" + url.PathEscape(userExternalID) + "/tables/customAccessLevels"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, fmt.Errorf("bamboohr: list entitlements: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bamboohr: list entitlements status %d: %s", resp.StatusCode, string(body))
	}
	var rows []bambooAccessLevelRow
	if err := json.Unmarshal(body, &rows); err != nil {
		var envelope struct {
			CustomAccessLevels []bambooAccessLevelRow `json:"customAccessLevels"`
		}
		if e2 := json.Unmarshal(body, &envelope); e2 != nil {
			return nil, fmt.Errorf("bamboohr: decode customAccessLevels: %w", err)
		}
		rows = envelope.CustomAccessLevels
	}
	out := make([]access.Entitlement, 0, len(rows))
	for _, r := range rows {
		out = append(out, access.Entitlement{
			ResourceExternalID: r.ID.String(),
			Role:               r.Value,
			Source:             "direct",
		})
	}
	return out, nil
}

func (c *BambooHRAccessConnector) GetSSOMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	host := c.ssoBaseURL(cfg)
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: host + "/saml/metadata",
		EntityID:    host,
	}, nil
}

func (c *BambooHRAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"subdomain": cfg.Subdomain,
		"auth_type": "api_key_basic",
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

var _ access.AccessConnector = (*BambooHRAccessConnector)(nil)
