// Package onepassword implements the access.AccessConnector contract for
// 1Password via its SCIM v2.0 bridge.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated /scim/v2/Users)
//   - GetSSOMetadata returns nil — 1Password is a vault, not an SSO provider
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real
//     implementations against the SCIM v2 /Groups and /Users endpoints.
package onepassword

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/connectors/connutil"
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OnePasswordAccessConnector implements access.AccessConnector for 1Password.
type OnePasswordAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

// New returns a fresh connector instance.
func New() *OnePasswordAccessConnector {
	return &OnePasswordAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *OnePasswordAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *OnePasswordAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/scim/v2/Users?count=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("onepassword: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes the SCIM Users endpoint for the sync_identity
// capability. Other capabilities are reported missing-with-no-probe.
func (c *OnePasswordAccessConnector) VerifyPermissions(
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
			req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/scim/v2/Users?count=1")
			if err != nil {
				return nil, err
			}
			if _, err := c.do(req); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities reads the SCIM ListResponse totalResults field.
func (c *OnePasswordAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/scim/v2/Users?count=1")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var lr scimListResponse
	if err := json.Unmarshal(body, &lr); err != nil {
		return 0, fmt.Errorf("onepassword: decode list response: %w", err)
	}
	return lr.TotalResults, nil
}

// SyncIdentities pages through /scim/v2/Users using SCIM startIndex/count
// pagination (1-based). The checkpoint is the next startIndex encoded as a
// decimal string; an empty checkpoint starts at 1.
func (c *OnePasswordAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startIndex := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			startIndex = n
		}
	}
	const count = 100
	for {
		path := fmt.Sprintf("/scim/v2/Users?count=%d&startIndex=%d", count, startIndex)
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var lr scimListResponse
		if err := json.Unmarshal(body, &lr); err != nil {
			return fmt.Errorf("onepassword: decode list response: %w", err)
		}
		batch := mapSCIMUsers(lr.Resources)
		nextCheckpoint := ""
		consumed := startIndex + len(lr.Resources) - 1
		if lr.TotalResults > 0 && consumed < lr.TotalResults {
			nextCheckpoint = strconv.Itoa(consumed + 1)
		} else if len(lr.Resources) == count && lr.TotalResults == 0 {
			// Some SCIM bridges omit totalResults — keep paging while
			// pages stay full.
			nextCheckpoint = strconv.Itoa(startIndex + count)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		startIndex, _ = strconv.Atoi(nextCheckpoint)
	}
}

// ---------- advanced capabilities ----------

// ProvisionAccess adds the user to the SCIM group via PATCH /scim/v2/Groups/{groupId}
// with the standard SCIM "add members" operation. 409 Conflict is treated as
// idempotent success.
func (c *OnePasswordAccessConnector) ProvisionAccess(
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
	patch := scimPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []scimPatchOperation{{
			Op:    "add",
			Path:  "members",
			Value: []scimMember{{Value: grant.UserExternalID}},
		}},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/scim/v2/Groups/%s", url.PathEscape(grant.ResourceExternalID))
	return c.scimMutate(ctx, cfg, secrets, http.MethodPatch, path, body, "provision")
}

// RevokeAccess removes the user from the SCIM group via PATCH with the
// "remove members[value eq \"...\"]" filter. 404 Not Found is idempotent
// success.
func (c *OnePasswordAccessConnector) RevokeAccess(
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
	patch := scimPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []scimPatchOperation{{
			Op:   "remove",
			Path: fmt.Sprintf("members[value eq %q]", grant.UserExternalID),
		}},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/scim/v2/Groups/%s", url.PathEscape(grant.ResourceExternalID))
	return c.scimMutate(ctx, cfg, secrets, http.MethodPatch, path, body, "revoke")
}

// ListEntitlements pulls the user's group memberships from
// GET /scim/v2/Users/{userId} (SCIM users include a "groups" array). Each
// group is mapped to Entitlement{ResourceExternalID: groupID, Role:
// groupDisplay, Source: "direct"}.
func (c *OnePasswordAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("onepassword: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, fmt.Sprintf("/scim/v2/Users/%s", url.PathEscape(userExternalID)))
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var user scimUserDetail
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("onepassword: decode user: %w", err)
	}
	out := make([]access.Entitlement, 0, len(user.Groups))
	for _, g := range user.Groups {
		out = append(out, access.Entitlement{
			ResourceExternalID: g.Value,
			Role:               g.Display,
			Source:             "direct",
		})
	}
	return out, nil
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("onepassword: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("onepassword: grant.ResourceExternalID is required")
	}
	return nil
}

// scimMutate dispatches a PATCH or POST mutation, treating 2xx + 409 as
// success for provision and 2xx + 404 as success for revoke.
func (c *OnePasswordAccessConnector) scimMutate(
	ctx context.Context,
	cfg Config,
	secrets Secrets,
	method, path string,
	body []byte,
	op string,
) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL(cfg)+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secrets.bearerToken())
	req.Header.Set("Accept", "application/scim+json")
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("onepassword: %s request: %w", op, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case op == "provision" && resp.StatusCode == http.StatusConflict:
		return nil
	case op == "revoke" && resp.StatusCode == http.StatusNotFound:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("onepassword: %s status %d: %s", op, resp.StatusCode, string(rb))
	}
}

type scimPatchOp struct {
	Schemas    []string             `json:"schemas"`
	Operations []scimPatchOperation `json:"Operations"`
}

type scimPatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

type scimMember struct {
	Value string `json:"value"`
}

type scimUserDetail struct {
	ID     string             `json:"id"`
	Groups []scimUserGroupRef `json:"groups"`
}

type scimUserGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display"`
}

// ---------- Metadata ----------

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker 1Password
// Business / Unlock-with-SSO SAML 2.0 SP federation. When `sso_metadata_url`
// is blank the helper returns (nil, nil) and the caller gracefully
// downgrades.
func (c *OnePasswordAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *OnePasswordAccessConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderName,
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

func (c *OnePasswordAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return c.urlOverride
	}
	return cfg.normalisedAccountURL()
}

// eventsBaseURL returns the base URL for the 1Password Events Reporting
// API. 1Password serves audit/sign-in events at events.1password.com,
// which is a different host from the SCIM bridge at scim.1password.com,
// so callers MUST NOT mix the two. Test paths can still inject a
// urlOverride to point both services at a single httptest.Server.
func (c *OnePasswordAccessConnector) eventsBaseURL(cfg Config) string {
	if c.urlOverride != "" {
		return c.urlOverride
	}
	return cfg.normalisedEventsAPIURL()
}

func (c *OnePasswordAccessConnector) newRequest(ctx context.Context, cfg Config, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL(cfg)+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secrets.bearerToken())
	req.Header.Set("Accept", "application/scim+json")
	return req, nil
}

func (c *OnePasswordAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("onepassword: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return connutil.ReadBody(resp.Body)
}

func (c *OnePasswordAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func mapSCIMUsers(users []scimUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := "active"
		if !u.Active {
			status = "disabled"
		}
		email := u.UserName
		for _, e := range u.Emails {
			if e.Primary || email == "" || !strings.Contains(email, "@") {
				email = e.Value
				if e.Primary {
					break
				}
			}
		}
		out = append(out, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.DisplayName,
			Email:       email,
			Status:      status,
		})
	}
	return out
}

// ---------- SCIM DTOs ----------

type scimListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []scimUser `json:"Resources"`
}

type scimUser struct {
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Active      bool        `json:"active"`
	Emails      []scimEmail `json:"emails,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*OnePasswordAccessConnector)(nil)
)
