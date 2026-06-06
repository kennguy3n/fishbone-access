// Package smartsheet implements the access.AccessConnector contract for the
// Smartsheet users API.
package smartsheet

import (
	"bytes"
	"context"
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
	ProviderName = "smartsheet"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("smartsheet: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type SmartsheetAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SmartsheetAccessConnector { return &SmartsheetAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("smartsheet: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("smartsheet: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("smartsheet: access_token is required")
	}
	return nil
}

func (c *SmartsheetAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SmartsheetAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.smartsheet.com"
}

func (c *SmartsheetAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SmartsheetAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *SmartsheetAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *SmartsheetAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("smartsheet: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *SmartsheetAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("smartsheet: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("smartsheet: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *SmartsheetAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SmartsheetAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/2.0/users/me"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("smartsheet: connect probe: %w", err)
	}
	return nil
}

func (c *SmartsheetAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type smartsheetUser struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Status    string `json:"status"`
}

type smartsheetResponse struct {
	PageNumber int              `json:"pageNumber"`
	PageSize   int              `json:"pageSize"`
	TotalPages int              `json:"totalPages"`
	TotalCount int              `json:"totalCount"`
	Data       []smartsheetUser `json:"data"`
}

func (c *SmartsheetAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SmartsheetAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
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
	base := c.baseURL()
	for {
		path := fmt.Sprintf("%s/2.0/users?page=%d&pageSize=%d", base, page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp smartsheetResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("smartsheet: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Data))
		for _, u := range resp.Data {
			display := u.Name
			if display == "" {
				display = strings.TrimSpace(u.FirstName + " " + u.LastName)
			}
			if display == "" {
				display = u.Email
			}
			status := "active"
			if u.Status != "" && !strings.EqualFold(u.Status, "active") {
				status = strings.ToLower(u.Status)
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", u.ID),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if resp.TotalPages > 0 && page < resp.TotalPages {
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

type smartsheetShare struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Email     string `json:"email,omitempty"`
	UserID    int64  `json:"userId,omitempty"`
	AccessLvl string `json:"accessLevel"`
}

type smartsheetSharesResponse struct {
	Data       []smartsheetShare `json:"data"`
	PageNumber int               `json:"pageNumber"`
	TotalPages int               `json:"totalPages"`
}

type smartsheetErrorBody struct {
	ErrorCode int    `json:"errorCode"`
	Message   string `json:"message"`
}

type smartsheetSheetSummary struct {
	ID        json.Number `json:"id"`
	Name      string      `json:"name"`
	AccessLvl string      `json:"accessLevel"`
}

func smartsheetAccessLevel(grantRole string) string {
	switch strings.ToUpper(strings.TrimSpace(grantRole)) {
	case "OWNER":
		return "OWNER"
	case "ADMIN":
		return "ADMIN"
	case "EDITOR_SHARE", "EDITOR":
		return "EDITOR"
	case "COMMENTER":
		return "COMMENTER"
	case "VIEWER", "":
		return "VIEWER"
	default:
		return strings.ToUpper(strings.TrimSpace(grantRole))
	}
}

// ProvisionAccess shares a Smartsheet sheet with a user via
// POST /2.0/sheets/{sheetId}/shares. ResourceExternalID = sheetId.
// UserExternalID = email. Smartsheet error code 1020 (duplicate share)
// and 4093 (already-shared variant) map to idempotent success.
func (c *SmartsheetAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("smartsheet: grant.UserExternalID (email) is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("smartsheet: grant.ResourceExternalID (sheetId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := []map[string]string{{
		"email":       grant.UserExternalID,
		"accessLevel": smartsheetAccessLevel(grant.Role),
	}}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("smartsheet: marshal payload: %w", err)
	}
	fullURL := c.baseURL() + "/2.0/sheets/" + url.PathEscape(grant.ResourceExternalID) + "/shares"
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
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var errBody smartsheetErrorBody
	_ = json.Unmarshal(respBody, &errBody)
	if errBody.ErrorCode == 1020 || errBody.ErrorCode == 4093 || bytes.Contains(bytes.ToLower(respBody), []byte("already shared")) {
		return nil
	}
	return fmt.Errorf("smartsheet: shares POST status %d: %s", resp.StatusCode, string(respBody))
}

// RevokeAccess removes a share from a sheet via
// DELETE /2.0/sheets/{sheetId}/shares/{shareId}. shareId is resolved by
// looking up the share whose email matches grant.UserExternalID.
func (c *SmartsheetAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("smartsheet: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("smartsheet: grant.ResourceExternalID (sheetId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	shareID, err := c.findShareIDForUser(ctx, secrets, grant.ResourceExternalID, grant.UserExternalID)
	if err != nil {
		return err
	}
	if shareID == "" {
		return nil
	}
	fullURL := c.baseURL() + "/2.0/sheets/" + url.PathEscape(grant.ResourceExternalID) + "/shares/" + url.PathEscape(shareID)
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, fullURL)
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
		return fmt.Errorf("smartsheet: shares DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

func (c *SmartsheetAccessConnector) findShareIDForUser(ctx context.Context, secrets Secrets, sheetID, email string) (string, error) {
	page := 1
	emailLower := strings.ToLower(strings.TrimSpace(email))
	for {
		fullURL := c.baseURL() + "/2.0/sheets/" + url.PathEscape(sheetID) + "/shares?pageSize=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return "", err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return "", err
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return "", nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("smartsheet: shares GET status %d: %s", resp.StatusCode, string(respBody))
		}
		var list smartsheetSharesResponse
		if err := json.Unmarshal(respBody, &list); err != nil {
			return "", fmt.Errorf("smartsheet: decode shares: %w", err)
		}
		for _, s := range list.Data {
			if strings.EqualFold(s.Email, emailLower) {
				return s.ID, nil
			}
		}
		if list.TotalPages <= list.PageNumber || list.PageNumber == 0 {
			return "", nil
		}
		page = list.PageNumber + 1
	}
}

// ListEntitlements paginates GET /2.0/sheets, then for each sheet
// checks /2.0/sheets/{sheetId}/shares for an entry matching the user.
// Returns one Entitlement per matched sheet with the per-share
// accessLevel.
//
// Cost: this issues 1 request per sheets page (page size = pageSize)
// plus 1 request per sheet returned by that page. Smartsheet has no
// per-user "my shared sheets" endpoint, so the per-sheet shares call is
// the only way to derive a user's access level. The outer loop honours
// ctx cancellation between pages and the inner loop honours it between
// per-sheet share lookups.
func (c *SmartsheetAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("smartsheet: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	emailLower := strings.ToLower(userExternalID)
	var out []access.Entitlement
	page := 1
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fullURL := c.baseURL() + "/2.0/sheets?pageSize=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Data       []smartsheetSheetSummary `json:"data"`
			PageNumber int                      `json:"pageNumber"`
			TotalPages int                      `json:"totalPages"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("smartsheet: decode sheets: %w", err)
		}
		for _, sheet := range resp.Data {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			role, err := c.lookupAccessLevelForUser(ctx, secrets, sheet.ID.String(), emailLower)
			if err != nil {
				return nil, err
			}
			if role == "" {
				continue
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: sheet.ID.String(),
				Role:               role,
				Source:             "direct",
			})
		}
		if resp.TotalPages <= resp.PageNumber || resp.PageNumber == 0 {
			return out, nil
		}
		page = resp.PageNumber + 1
	}
}

// lookupAccessLevelForUser paginates through /2.0/sheets/{sheetId}/shares
// and returns the accessLevel for the share whose email matches
// emailLower (case-insensitive). Mirrors the pagination loop in
// findShareIDForUser so sheets with more than pageSize collaborators are
// not silently dropped. ctx cancellation is honoured between pages.
func (c *SmartsheetAccessConnector) lookupAccessLevelForUser(ctx context.Context, secrets Secrets, sheetID, emailLower string) (string, error) {
	page := 1
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		fullURL := c.baseURL() + "/2.0/sheets/" + url.PathEscape(sheetID) + "/shares?pageSize=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return "", err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return "", nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("smartsheet: shares GET status %d: %s", resp.StatusCode, string(body))
		}
		var list smartsheetSharesResponse
		if err := json.Unmarshal(body, &list); err != nil {
			return "", fmt.Errorf("smartsheet: decode shares: %w", err)
		}
		for _, s := range list.Data {
			if strings.EqualFold(s.Email, emailLower) {
				return s.AccessLvl, nil
			}
		}
		if list.TotalPages <= list.PageNumber || list.PageNumber == 0 {
			return "", nil
		}
		page = list.PageNumber + 1
	}
}

// GetSSOMetadata returns Smartsheet SAML federation metadata when the
// operator supplies `sso_metadata_url` in the connector config.
func (c *SmartsheetAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SmartsheetAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
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

var _ access.AccessConnector = (*SmartsheetAccessConnector)(nil)
