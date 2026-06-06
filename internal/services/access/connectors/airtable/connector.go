// Package airtable implements the access.AccessConnector contract for the
// Airtable Enterprise Account users API.
package airtable

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
	ProviderName   = "airtable"
	defaultBaseURL = "https://api.airtable.com/v0"
)

var ErrNotImplemented = fmt.Errorf("airtable: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	EnterpriseID string `json:"enterprise_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type AirtableAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *AirtableAccessConnector { return &AirtableAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("airtable: config is nil")
	}
	var cfg Config
	if v, ok := raw["enterprise_id"].(string); ok {
		cfg.EnterpriseID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("airtable: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.EnterpriseID) == "" {
		return errors.New("airtable: enterprise_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("airtable: access_token is required")
	}
	return nil
}

func (c *AirtableAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *AirtableAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *AirtableAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *AirtableAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *AirtableAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *AirtableAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("airtable: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *AirtableAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("airtable: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("airtable: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *AirtableAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *AirtableAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/meta/enterpriseAccount/"+cfg.EnterpriseID)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("airtable: connect probe: %w", err)
	}
	return nil
}

func (c *AirtableAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type airtableUsersResponse struct {
	Users  []airtableUser `json:"users"`
	Offset string         `json:"offset,omitempty"`
}

type airtableUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	State string `json:"state,omitempty"`
}

func (c *AirtableAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *AirtableAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := checkpoint
	for {
		path := "/meta/enterpriseAccount/" + cfg.EnterpriseID + "/users?pageSize=100"
		if offset != "" {
			path += "&offset=" + offset
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp airtableUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("airtable: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users))
		for _, u := range resp.Users {
			status := "active"
			if u.State != "" && !strings.EqualFold(u.State, "active") {
				status = strings.ToLower(u.State)
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
		next := resp.Offset
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset = next
	}
}

// ---------- advanced capabilities ----------

type airtableCollaborator struct {
	UserID     string `json:"userId"`
	Email      string `json:"email"`
	Permission string `json:"permissionLevel"`
	GranularID string `json:"granularId,omitempty"`
}

type airtableBaseCollaboratorsResponse struct {
	IndividualCollaborators []airtableCollaborator `json:"individualCollaborators"`
}

func airtablePermission(grantRole string) string {
	switch strings.ToLower(strings.TrimSpace(grantRole)) {
	case "owner":
		return "owner"
	case "create", "creator":
		return "create"
	case "edit", "editor":
		return "edit"
	case "comment", "commenter":
		return "comment"
	case "read", "reader", "":
		return "read"
	default:
		return strings.ToLower(strings.TrimSpace(grantRole))
	}
}

// ProvisionAccess adds a collaborator to an Airtable base via
// POST /meta/bases/{baseId}/collaborators. ResourceExternalID = baseId,
// UserExternalID = user-id-or-email. Duplicate collaborator errors
// (422 + "already collaborator") are treated as idempotent success.
func (c *AirtableAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("airtable: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("airtable: grant.ResourceExternalID (baseId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	collaborator := map[string]string{"permissionLevel": airtablePermission(grant.Role)}
	if strings.Contains(grant.UserExternalID, "@") {
		collaborator["email"] = grant.UserExternalID
	} else {
		collaborator["userId"] = grant.UserExternalID
	}
	body, err := json.Marshal(map[string]interface{}{"collaborators": []map[string]string{collaborator}})
	if err != nil {
		return fmt.Errorf("airtable: marshal payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, "/meta/bases/"+url.PathEscape(grant.ResourceExternalID)+"/collaborators", body)
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
	case (resp.StatusCode == http.StatusUnprocessableEntity || resp.StatusCode == http.StatusBadRequest) && bytes.Contains(bytes.ToLower(respBody), []byte("already")):
		return nil
	default:
		return fmt.Errorf("airtable: base collaborators POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a collaborator from an Airtable base via
// DELETE /meta/bases/{baseId}/collaborators/{collaboratorId}. 404 is
// idempotent success. When grant.UserExternalID is an email rather than a
// user-id we resolve it via GET /meta/bases/{baseId}/collaborators.
func (c *AirtableAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("airtable: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("airtable: grant.ResourceExternalID (baseId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	collabID := grant.UserExternalID
	if strings.Contains(collabID, "@") {
		resolved, err := c.findCollaboratorIDForEmail(ctx, secrets, grant.ResourceExternalID, collabID)
		if err != nil {
			return err
		}
		if resolved == "" {
			// no collaborator with that email ⇒ idempotent success
			return nil
		}
		collabID = resolved
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, "/meta/bases/"+url.PathEscape(grant.ResourceExternalID)+"/collaborators/"+url.PathEscape(collabID))
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
		return fmt.Errorf("airtable: base collaborators DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

func (c *AirtableAccessConnector) findCollaboratorIDForEmail(ctx context.Context, secrets Secrets, baseID, email string) (string, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/meta/bases/"+url.PathEscape(baseID)+"/collaborators")
	if err != nil {
		return "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("airtable: list collaborators status %d: %s", resp.StatusCode, string(body))
	}
	var list airtableBaseCollaboratorsResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return "", fmt.Errorf("airtable: decode collaborators: %w", err)
	}
	emailLower := strings.ToLower(strings.TrimSpace(email))
	for _, cc := range list.IndividualCollaborators {
		if strings.ToLower(strings.TrimSpace(cc.Email)) == emailLower {
			return cc.UserID, nil
		}
	}
	return "", nil
}

// ListEntitlements walks /meta/bases and emits one Entitlement per base
// where the user appears as an individual collaborator. Airtable's
// per-user "my bases" endpoint is restricted to the authed user, so we
// enumerate bases and filter.
//
// Airtable's /meta/bases response often omits the inline
// individualCollaborators array (it's only present when the caller has
// the meta:read scope and an enterprise plan). When the inline list is
// missing we fall back to a per-base GET /meta/bases/{baseId}/collaborators
// call so the entitlement listing still works on standard plans. The
// loop honours ctx cancellation between per-base calls.
func (c *AirtableAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("airtable: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/meta/bases")
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Bases []struct {
			ID                      string                 `json:"id"`
			Name                    string                 `json:"name"`
			PermissionLevel         string                 `json:"permissionLevel,omitempty"`
			IndividualCollaborators []airtableCollaborator `json:"individualCollaborators,omitempty"`
		} `json:"bases"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("airtable: decode bases: %w", err)
	}
	needle := strings.ToLower(userExternalID)
	var out []access.Entitlement
	for _, b := range resp.Bases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		collabs := b.IndividualCollaborators
		if len(collabs) == 0 {
			perBase, err := c.listBaseCollaborators(ctx, secrets, b.ID)
			if err != nil {
				return nil, err
			}
			collabs = perBase
		}
		for _, cc := range collabs {
			if strings.EqualFold(cc.UserID, userExternalID) || strings.EqualFold(cc.Email, needle) {
				role := cc.Permission
				if role == "" {
					role = "read"
				}
				out = append(out, access.Entitlement{
					ResourceExternalID: b.ID,
					Role:               role,
					Source:             "direct",
				})
				break
			}
		}
	}
	return out, nil
}

// listBaseCollaborators issues GET /meta/bases/{baseId}/collaborators
// and returns the individual collaborators array. Used as a fallback
// when /meta/bases omits the inline IndividualCollaborators field. A
// 404 is treated as "no collaborators" rather than an error so the
// outer ListEntitlements call can continue past inaccessible bases.
func (c *AirtableAccessConnector) listBaseCollaborators(ctx context.Context, secrets Secrets, baseID string) ([]airtableCollaborator, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/meta/bases/"+url.PathEscape(baseID)+"/collaborators")
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("airtable: base collaborators GET status %d: %s", resp.StatusCode, string(body))
	}
	var list airtableBaseCollaboratorsResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("airtable: decode base collaborators: %w", err)
	}
	return list.IndividualCollaborators, nil
}

// GetSSOMetadata returns Airtable SAML federation metadata when the
// operator supplies `sso_metadata_url` in the connector config.
func (c *AirtableAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *AirtableAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":      ProviderName,
		"enterprise_id": cfg.EnterpriseID,
		"auth_type":     "access_token",
		"token_short":   shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*AirtableAccessConnector)(nil)
