// Package duo implements the access.AccessConnector contract for the Duo
// Security Admin API.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities (admin/v1/info/summary)
//   - SyncIdentities (paginated /admin/v1/users)
//   - GetSSOMetadata returns nil — Duo is MFA, not SSO
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real
//     implementations against /admin/v1/users/{userId}/groups (HMAC-SHA1).
package duo

import (
	"context"
	"crypto/hmac"
	// gosec G505 false positive: Duo Admin API v1 mandates
	// HMAC-SHA1 for request signing. Protocol requirement, not
	// a cryptographic strength choice.
	"crypto/sha1" // #nosec G505
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("duo_security: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DuoAccessConnector implements access.AccessConnector for Duo Security.
type DuoAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
	// nowFn lets tests pin the request Date header for stable signature
	// snapshots; production paths leave it nil and use time.Now.
	nowFn func() time.Time
}

// New returns a fresh connector instance.
func New() *DuoAccessConnector {
	return &DuoAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *DuoAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DuoAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.fetchSummary(ctx, cfg, secrets); err != nil {
		return fmt.Errorf("duo_security: connect: %w", err)
	}
	return nil
}

// VerifyPermissions probes /admin/v1/info/summary for sync_identity.
func (c *DuoAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sync_identity":
			if _, err := c.fetchSummary(ctx, cfg, secrets); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities returns the user_count exposed by /admin/v1/info/summary.
func (c *DuoAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	summary, err := c.fetchSummary(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	return summary.UserCount, nil
}

// SyncIdentities pages through /admin/v1/users using offset/limit pagination.
// The checkpoint is the next offset encoded as a decimal string.
func (c *DuoAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil {
			offset = n
		}
	}
	const limit = 300
	for {
		params := map[string]string{
			"limit":  strconv.Itoa(limit),
			"offset": strconv.Itoa(offset),
		}
		var resp duoUsersResponse
		if err := c.signedJSON(ctx, cfg, secrets, http.MethodGet, "/admin/v1/users", params, &resp); err != nil {
			return err
		}
		batch := mapDuoUsers(resp.Response)
		nextCheckpoint := ""
		if resp.Metadata != nil && resp.Metadata.NextOffset != nil {
			nextCheckpoint = strconv.Itoa(*resp.Metadata.NextOffset)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		offset = *resp.Metadata.NextOffset
	}
}

// ---------- advanced capabilities ----------

// ProvisionAccess adds the user to a Duo group via POST
// /admin/v1/users/{userId}/groups (form-encoded group_id parameter). 400/409
// with an "already a member" body is treated as idempotent success.
func (c *DuoAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/admin/v1/users/%s/groups", url.PathEscape(grant.UserExternalID))
	params := map[string]string{"group_id": grant.ResourceExternalID}
	status, body, err := c.signedRaw(ctx, cfg, secrets, http.MethodPost, path, params)
	if err != nil {
		return fmt.Errorf("duo_security: provision request: %w", err)
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusConflict:
		return nil
	case status == http.StatusBadRequest && bytesContains(body, "already a member"):
		return nil
	default:
		return fmt.Errorf("duo_security: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the user from the Duo group via DELETE
// /admin/v1/users/{userId}/groups/{groupId}. 404 is idempotent success.
func (c *DuoAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/admin/v1/users/%s/groups/%s",
		url.PathEscape(grant.UserExternalID), url.PathEscape(grant.ResourceExternalID))
	status, body, err := c.signedRaw(ctx, cfg, secrets, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("duo_security: revoke request: %w", err)
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("duo_security: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the user's group memberships via GET
// /admin/v1/users/{userId}/groups. Each group is mapped to
// Entitlement{ResourceExternalID: groupID, Role: groupName, Source: "direct"}.
func (c *DuoAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("duo_security: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/admin/v1/users/%s/groups", url.PathEscape(userExternalID))
	var resp duoUserGroupsResponse
	if err := c.signedJSON(ctx, cfg, secrets, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	out := make([]access.Entitlement, 0, len(resp.Response))
	for _, g := range resp.Response {
		out = append(out, access.Entitlement{
			ResourceExternalID: g.GroupID,
			Role:               g.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("duo_security: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("duo_security: grant.ResourceExternalID is required")
	}
	return nil
}

func bytesContains(haystack []byte, needle string) bool {
	return strings.Contains(string(haystack), needle)
}

type duoUserGroupsResponse struct {
	Stat     string         `json:"stat"`
	Response []duoUserGroup `json:"response"`
}

type duoUserGroup struct {
	GroupID string `json:"group_id"`
	Name    string `json:"name"`
}

// ---------- Metadata ----------

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Duo SSO
// (Cisco Duo's hosted SAML 2.0 SP for the Admin Panel) federation. When
// `sso_metadata_url` is blank the helper returns (nil, nil) and the caller
// gracefully downgrades.
func (c *DuoAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *DuoAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":        ProviderName,
		"integration_key": s.IntegrationKey,
	}, nil
}

// ---------- Internal helpers ----------

func decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *DuoAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return c.urlOverride
	}
	return "https://" + cfg.normalisedHost()
}

func (c *DuoAccessConnector) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now().UTC()
}

// signDuoRequest builds the Duo Admin API HMAC-SHA1 signature per
// https://duo.com/docs/adminapi#authentication. The signed string is:
//
//	date\n
//	METHOD\n
//	HOST\n   (lower-case, no port)
//	path\n
//	canonical-params (RFC 3986 encoded, sorted by key)
//
// The HMAC is keyed with secret_key and rendered as lower-case hex. The
// final Authorization header is "Basic base64(ikey:signature)".
func signDuoRequest(method, host, path string, params map[string]string, ikey, skey, date string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(url.QueryEscape(k))
		canonical.WriteByte('=')
		canonical.WriteString(url.QueryEscape(params[k]))
	}
	stringToSign := strings.Join([]string{
		date,
		strings.ToUpper(method),
		strings.ToLower(host),
		path,
		canonical.String(),
	}, "\n")

	mac := hmac.New(sha1.New, []byte(skey))
	mac.Write([]byte(stringToSign))
	sig := hex.EncodeToString(mac.Sum(nil))

	auth := ikey + ":" + sig
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (c *DuoAccessConnector) signedJSON(
	ctx context.Context,
	cfg Config,
	secrets Secrets,
	method, path string,
	params map[string]string,
	out interface{},
) error {
	if params == nil {
		params = map[string]string{}
	}
	host := cfg.normalisedHost()
	date := c.now().Format(time.RFC1123Z)

	authHeader := signDuoRequest(method, host, path, params, secrets.IntegrationKey, secrets.SecretKey, date)

	reqURL := c.baseURL(cfg) + path
	if method == http.MethodGet && len(params) > 0 {
		v := url.Values{}
		for k, val := range params {
			v.Set(k, val)
		}
		reqURL = reqURL + "?" + v.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Date", date)
	req.Header.Set("Accept", "application/json")

	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("duo_security: %s status %d: %s", path, resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("duo_security: decode %s: %w", path, err)
		}
	}
	return nil
}

func (c *DuoAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// signedRaw builds and dispatches a Duo-signed request, returning the
// status code and body (already drained — body is closed inside this
// helper). Unlike signedJSON it does not translate non-2xx into an
// error — callers that need to special-case 404/409 idempotency use
// this entry point.
//
// Returning a primitive (status, body, err) tuple — instead of the
// live *http.Response — keeps body-lifetime ownership inside the
// helper and makes it impossible for a caller to leak the body. It
// also closes the bodyclose lint false-positive that would otherwise
// fire on every caller (the linter cannot see through helpers that
// close the body internally).
func (c *DuoAccessConnector) signedRaw(
	ctx context.Context,
	cfg Config,
	secrets Secrets,
	method, path string,
	params map[string]string,
) (int, []byte, error) {
	if params == nil {
		params = map[string]string{}
	}
	host := cfg.normalisedHost()
	date := c.now().Format(time.RFC1123Z)
	authHeader := signDuoRequest(method, host, path, params, secrets.IntegrationKey, secrets.SecretKey, date)

	reqURL := c.baseURL(cfg) + path
	var bodyReader io.Reader
	if method == http.MethodGet && len(params) > 0 {
		v := url.Values{}
		for k, val := range params {
			v.Set(k, val)
		}
		reqURL = reqURL + "?" + v.Encode()
	} else if method != http.MethodGet && len(params) > 0 {
		v := url.Values{}
		for k, val := range params {
			v.Set(k, val)
		}
		bodyReader = strings.NewReader(v.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Date", date)
	req.Header.Set("Accept", "application/json")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, body, nil
}

func (c *DuoAccessConnector) fetchSummary(ctx context.Context, cfg Config, secrets Secrets) (*duoSummary, error) {
	var resp duoSummaryResponse
	if err := c.signedJSON(ctx, cfg, secrets, http.MethodGet, "/admin/v1/info/summary", nil, &resp); err != nil {
		return nil, err
	}
	if resp.Stat != "" && resp.Stat != "OK" {
		return nil, fmt.Errorf("duo_security: summary stat=%q", resp.Stat)
	}
	return &resp.Response, nil
}

func mapDuoUsers(users []duoUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := strings.ToLower(u.Status)
		if status == "" {
			status = "active"
		}
		email := u.Email
		if email == "" {
			email = u.Username
		}
		out = append(out, &access.Identity{
			ExternalID:  u.UserID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.RealName,
			Email:       email,
			Status:      status,
		})
	}
	return out
}

// ---------- Duo DTOs ----------

type duoUsersResponse struct {
	Stat     string       `json:"stat"`
	Response []duoUser    `json:"response"`
	Metadata *duoMetadata `json:"metadata,omitempty"`
}

type duoMetadata struct {
	NextOffset   *int `json:"next_offset,omitempty"`
	TotalObjects int  `json:"total_objects,omitempty"`
}

type duoUser struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	RealName string `json:"realname"`
	Status   string `json:"status"`
}

type duoSummaryResponse struct {
	Stat     string     `json:"stat"`
	Response duoSummary `json:"response"`
}

type duoSummary struct {
	UserCount        int `json:"user_count"`
	IntegrationCount int `json:"integration_count,omitempty"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*DuoAccessConnector)(nil)
)
