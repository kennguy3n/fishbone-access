// Package tenable implements the access.AccessConnector contract for the
// Tenable.io /users API.
//
// Tenable.io authenticates with two keys passed together in a single
// `X-ApiKeys` header (`accessKey={ak};secretKey={sk}`). Both keys are
// required. /users is paginated with `offset`/`limit` and returns a flat
// `users` array; the connector tracks the offset as a stringified
// integer in `checkpoint`.
package tenable

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
	ProviderName = "tenable"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("tenable: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type TenableAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *TenableAccessConnector { return &TenableAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("tenable: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("tenable: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_key"].(string); ok {
		s.AccessKey = v
	}
	if v, ok := raw["secret_key"].(string); ok {
		s.SecretKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessKey) == "" {
		return errors.New("tenable: access_key is required")
	}
	if strings.TrimSpace(s.SecretKey) == "" {
		return errors.New("tenable: secret_key is required")
	}
	return nil
}

func (c *TenableAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *TenableAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://cloud.tenable.com"
}

func (c *TenableAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *TenableAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-ApiKeys",
		"accessKey="+strings.TrimSpace(secrets.AccessKey)+";"+
			"secretKey="+strings.TrimSpace(secrets.SecretKey))
	return req, nil
}

func (c *TenableAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ApiKeys",
		"accessKey="+strings.TrimSpace(secrets.AccessKey)+";"+
			"secretKey="+strings.TrimSpace(secrets.SecretKey))
	return req, nil
}

func (c *TenableAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("tenable: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *TenableAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("tenable: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("tenable: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *TenableAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *TenableAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/users?offset=0&limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("tenable: connect probe: %w", err)
	}
	return nil
}

func (c *TenableAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type tenableUser struct {
	ID       json.Number `json:"id"`
	UUID     string      `json:"uuid"`
	Username string      `json:"username"`
	Email    string      `json:"email"`
	Name     string      `json:"name"`
	Enabled  bool        `json:"enabled"`
}

type tenableListResponse struct {
	Users []tenableUser `json:"users"`
}

func (c *TenableAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *TenableAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
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
		q := url.Values{
			"offset": []string{fmt.Sprintf("%d", offset)},
			"limit":  []string{fmt.Sprintf("%d", pageSize)},
		}
		fullURL := c.baseURL() + "/users?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp tenableListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("tenable: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			external := u.UUID
			if external == "" {
				external = u.ID.String()
			}
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = strings.TrimSpace(u.Username)
			}
			if display == "" {
				display = u.Email
			}
			status := "active"
			if !u.Enabled {
				status = "disabled"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  external,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      status,
			})
		}
		next := ""
		if len(resp.Users) == pageSize {
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

type tenableGroupRef struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
}

type tenableUserDetail struct {
	ID     int               `json:"id"`
	UUID   string            `json:"uuid,omitempty"`
	Groups []tenableGroupRef `json:"groups"`
}

func tenableGroupID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("tenable: ResourceExternalID is required")
	}
	return s, nil
}

// ProvisionAccess adds a user to a group via
// POST /groups/{groupId}/users/{userId}. 409 ⇒ idempotent success.
func (c *TenableAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("tenable: grant.UserExternalID is required")
	}
	groupID, err := tenableGroupID(grant.ResourceExternalID)
	if err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	fullURL := c.baseURL() + "/groups/" + url.PathEscape(groupID) + "/users/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, fullURL, []byte(`{}`))
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
		return fmt.Errorf("tenable: group POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a group via
// DELETE /groups/{groupId}/users/{userId}. 404 ⇒ idempotent success.
func (c *TenableAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("tenable: grant.UserExternalID is required")
	}
	groupID, err := tenableGroupID(grant.ResourceExternalID)
	if err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	fullURL := c.baseURL() + "/groups/" + url.PathEscape(groupID) + "/users/" + url.PathEscape(grant.UserExternalID)
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
		return fmt.Errorf("tenable: group DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements reads /users/{userId} and emits one Entitlement
// per group membership.
func (c *TenableAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("tenable: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	fullURL := c.baseURL() + "/users/" + url.PathEscape(userExternalID)
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
		return nil, fmt.Errorf("tenable: user GET status %d: %s", resp.StatusCode, string(body))
	}
	var detail tenableUserDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return nil, fmt.Errorf("tenable: decode user: %w", err)
	}
	out := make([]access.Entitlement, 0, len(detail.Groups))
	for _, g := range detail.Groups {
		out = append(out, access.Entitlement{
			ResourceExternalID: fmt.Sprintf("%d", g.ID),
			Role:               g.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker
// Tenable.io / Tenable.sc SSO federation. When `sso_metadata_url` is blank
// the helper returns (nil, nil) and the caller gracefully downgrades.
func (c *TenableAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *TenableAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":         ProviderName,
		"auth_type":        "x_api_keys",
		"access_key_short": shortToken(secrets.AccessKey),
		"secret_key_short": shortToken(secrets.SecretKey),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*TenableAccessConnector)(nil)
