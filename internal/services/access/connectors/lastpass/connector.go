// Package lastpass implements the access.AccessConnector contract for
// LastPass Enterprise via its enterpriseapi.php JSON endpoint.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated cmd=getuserdata)
//   - GetSSOMetadata returns nil — LastPass is a vault, not an SSO provider
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real
//     implementations against the cmd=batchchangegrp / cmd=getsfdata
//     LastPass enterprise endpoints.
package lastpass

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// defaultEndpoint is the LastPass Enterprise JSON API URL. Tests override it
// via urlOverride.
const defaultEndpoint = "https://lastpass.com/enterpriseapi.php"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// LastPassAccessConnector implements access.AccessConnector for LastPass
// Enterprise.
type LastPassAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

// New returns a fresh connector instance.
func New() *LastPassAccessConnector {
	return &LastPassAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *LastPassAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *LastPassAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{"pagesize": 1})
	if _, err := c.postJSON(ctx, body); err != nil {
		return fmt.Errorf("lastpass: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes cmd=getuserdata for the sync_identity capability.
func (c *LastPassAccessConnector) VerifyPermissions(
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
			body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{"pagesize": 1})
			if _, err := c.postJSON(ctx, body); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities calls cmd=getuserdata with pagesize=1 and reads the total
// from the response.
func (c *LastPassAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{"pagesize": 1})
	respBody, err := c.postJSON(ctx, body)
	if err != nil {
		return 0, err
	}
	var resp lastpassUserDataResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return 0, fmt.Errorf("lastpass: decode getuserdata: %w", err)
	}
	return resp.Total, nil
}

// SyncIdentities pages through cmd=getuserdata using pageoffset/pagesize.
// The checkpoint is the next pageoffset encoded as a decimal string; an
// empty checkpoint starts at 0.
func (c *LastPassAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	const pageSize = 100
	pageOffset := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			pageOffset = n
		}
	}
	for {
		body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{
			"pagesize":   pageSize,
			"pageoffset": pageOffset,
		})
		respBody, err := c.postJSON(ctx, body)
		if err != nil {
			return err
		}
		var resp lastpassUserDataResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("lastpass: decode getuserdata: %w", err)
		}
		batch := mapLastPassUsers(resp.Users)
		nextCheckpoint := ""
		consumed := pageOffset + len(resp.Users)
		if (resp.Total > 0 && consumed < resp.Total) ||
			(resp.Total == 0 && len(resp.Users) == pageSize) {
			nextCheckpoint = strconv.Itoa(consumed)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		pageOffset = consumed
	}
}

// ---------- advanced capabilities ----------

// ProvisionAccess adds the user to a LastPass shared group (cmd=batchchangegrp
// with op=add). The LastPass admin API returns a JSON body whose top-level
// status is "OK" on success or "FAIL" with an error message otherwise; we
// treat "already a member" / "alreadyinthegroup" as idempotent success.
func (c *LastPassAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	return c.batchChangeGroup(ctx, configRaw, secretsRaw, grant, "add")
}

// RevokeAccess removes the user from a LastPass shared group (cmd=batchchangegrp
// with op=del). "not a member" / "notinthegroup" responses are treated as
// idempotent success.
func (c *LastPassAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	return c.batchChangeGroup(ctx, configRaw, secretsRaw, grant, "del")
}

// ListEntitlements returns all shared groups the user is a member of via
// cmd=getsfdata (shared-folder + group membership). Each group is mapped to
// Entitlement{ResourceExternalID: groupName, Role: groupName, Source: "direct"}.
func (c *LastPassAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("lastpass: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	body := buildPayload(cfg, secrets, "getsfdata", map[string]interface{}{
		"user": userExternalID,
	})
	respBody, err := c.postJSON(ctx, body)
	if err != nil {
		return nil, err
	}
	var resp lastpassSharedFolderDataResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("lastpass: decode getsfdata: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Folders))
	for _, f := range resp.Folders {
		if !folderHasMember(f, userExternalID) {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: f.SharedFolderID,
			Role:               f.SharedFolderName,
			Source:             "direct",
		})
	}
	return out, nil
}

func (c *LastPassAccessConnector) batchChangeGroup(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
	op string,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body := buildPayload(cfg, secrets, "batchchangegrp", map[string]interface{}{
		"groupname": grant.ResourceExternalID,
		"username":  grant.UserExternalID,
		"op":        op,
	})
	respBody, err := c.postJSONAllowFail(ctx, body)
	if err != nil {
		return err
	}
	// Decode the status field rather than substring-matching the raw body so
	// formatting/whitespace (e.g. `"status": "OK"`) can't mask a success,
	// matching postJSON's robustness.
	var probe struct {
		Status string   `json:"status"`
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(respBody, &probe)
	if strings.EqualFold(strings.TrimSpace(probe.Status), "ok") {
		return nil
	}
	// LastPass reports "already in group" / "not in group" as FAIL responses;
	// treat them as idempotent successes. Match the decoded error fields,
	// falling back to the raw body so we stay resilient to shape changes.
	msg := strings.ToLower(strings.Join(append(probe.Errors, probe.Error), " "))
	if strings.TrimSpace(msg) == "" {
		msg = strings.ToLower(string(respBody))
	}
	if op == "add" && strings.Contains(msg, "already") {
		return nil
	}
	if op == "del" && (strings.Contains(msg, "not in") || strings.Contains(msg, "notinthegroup") || strings.Contains(msg, "notmember")) {
		return nil
	}
	return fmt.Errorf("lastpass: %s status FAIL: %s", op, string(respBody))
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("lastpass: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("lastpass: grant.ResourceExternalID is required")
	}
	return nil
}

func folderHasMember(f lastpassSharedFolder, user string) bool {
	for _, u := range f.Users {
		if strings.EqualFold(u.Username, user) || u.UserID == user {
			return true
		}
	}
	return false
}

type lastpassSharedFolderDataResponse struct {
	Folders []lastpassSharedFolder `json:"folders"`
}

type lastpassSharedFolder struct {
	SharedFolderID   string                 `json:"sharedfolderid"`
	SharedFolderName string                 `json:"sharedfoldername"`
	Users            []lastpassFolderMember `json:"users"`
}

type lastpassFolderMember struct {
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username"`
}

// ---------- Metadata ----------

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker LastPass
// Business federated-login SAML 2.0 SP federation (LastPass Business / Teams
// supports SAML SSO via the operator-supplied IdP metadata URL). When
// `sso_metadata_url` is blank the helper returns (nil, nil) and the caller
// gracefully downgrades.
func (c *LastPassAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *LastPassAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, _ map[string]interface{}) (map[string]interface{}, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"account_number": cfg.AccountNumber,
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

func (c *LastPassAccessConnector) endpoint() string {
	if c.urlOverride != "" {
		return c.urlOverride
	}
	return defaultEndpoint
}

func buildPayload(cfg Config, secrets Secrets, cmd string, data map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"cid":      cfg.AccountNumber,
		"provhash": secrets.ProvisioningHash,
		"cmd":      cmd,
		"data":     data,
	}
}

func (c *LastPassAccessConnector) postJSON(ctx context.Context, body map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("lastpass: status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	// LastPass returns HTTP 200 even on logical errors, signalling them
	// with a top-level {"status":"FAIL"}. Decode the status field rather
	// than substring-matching the raw bytes, so the check is insensitive
	// to JSON whitespace and key ordering. Non-object payloads (the
	// reporting array shape, user/folder lists) leave status empty and
	// pass through unchanged.
	var probe struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(respBody, &probe)
	if strings.EqualFold(strings.TrimSpace(probe.Status), "FAIL") {
		return nil, fmt.Errorf("lastpass: api FAIL: %s", string(respBody))
	}
	return respBody, nil
}

func (c *LastPassAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// postJSONAllowFail mirrors postJSON but does not translate the LastPass
// "status":"FAIL" body into an error — callers (provision/revoke) inspect
// the body themselves to detect idempotent "already a member" responses.
func (c *LastPassAccessConnector) postJSONAllowFail(ctx context.Context, body map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("lastpass: status %d: %s", resp.StatusCode, string(respBody))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func mapLastPassUsers(users []lastpassUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := "active"
		if u.Disabled {
			status = "disabled"
		}
		email := u.Username
		if u.Email != "" {
			email = u.Email
		}
		externalID := u.UserID
		if externalID == "" {
			externalID = u.Username
		}
		out = append(out, &access.Identity{
			ExternalID:  externalID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.FullName,
			Email:       email,
			Status:      status,
		})
	}
	return out
}

// ---------- LastPass DTOs ----------

type lastpassUserDataResponse struct {
	Total int            `json:"total"`
	Users []lastpassUser `json:"Users"`
}

type lastpassUser struct {
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	FullName string `json:"fullname"`
	Disabled bool   `json:"disabled"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*LastPassAccessConnector)(nil)
)
