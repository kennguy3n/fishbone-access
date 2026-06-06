// Package intercom implements the access.AccessConnector contract for the
// Intercom /admins API.
//
// Intercom's /admins endpoint returns the entire workspace admin roster
// in a single response — there is no pagination cursor — so this
// connector is single-page by design.
package intercom

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

const ProviderName = "intercom"

var ErrNotImplemented = fmt.Errorf("intercom: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type IntercomAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *IntercomAccessConnector { return &IntercomAccessConnector{} }
func init()                         { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("intercom: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("intercom: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("intercom: token is required")
	}
	return nil
}

func (c *IntercomAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *IntercomAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.intercom.io"
}

func (c *IntercomAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *IntercomAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *IntercomAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *IntercomAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("intercom: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *IntercomAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("intercom: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("intercom: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *IntercomAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *IntercomAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/admins"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("intercom: connect probe: %w", err)
	}
	return nil
}

func (c *IntercomAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type intercomAdmin struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Away  bool   `json:"away_mode_enabled"`
}

type intercomListResponse struct {
	Type   string          `json:"type"`
	Admins []intercomAdmin `json:"admins"`
}

func (c *IntercomAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *IntercomAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := c.baseURL() + "/admins"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp intercomListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("intercom: decode admins: %w", err)
	}
	identities := make([]*access.Identity, 0, len(resp.Admins))
	for _, a := range resp.Admins {
		display := a.Name
		if display == "" {
			display = a.Email
		}
		status := "active"
		if a.Away {
			status = "away"
		}
		identities = append(identities, &access.Identity{
			ExternalID:  a.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       a.Email,
			Status:      status,
		})
	}
	return handler(identities, "")
}

// ---------- advanced capabilities ----------

type intercomTeam struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	AdminIDs []string `json:"admin_ids"`
}

type intercomTeamsResponse struct {
	Teams []intercomTeam `json:"teams"`
}

func (c *IntercomAccessConnector) getTeam(ctx context.Context, secrets Secrets, teamID string) (*intercomTeam, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/teams/"+url.PathEscape(teamID))
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Read the body up-front so the underlying TCP connection is
	// always returned to the keepalive pool on every status code,
	// matching the putTeamAdmins idiom in the same file. Leaver
	// flows that loop SyncGroupMembers over deleted teams hit this
	// 404 path repeatedly, so the drain is load-bearing.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("intercom: team GET status %d: %s", resp.StatusCode, string(body))
	}
	var team intercomTeam
	if err := json.Unmarshal(body, &team); err != nil {
		return nil, fmt.Errorf("intercom: decode team: %w", err)
	}
	return &team, nil
}

func (c *IntercomAccessConnector) putTeamAdmins(ctx context.Context, secrets Secrets, teamID string, adminIDs []string) error {
	payload := map[string]interface{}{"admin_ids": adminIDs}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("intercom: marshal team payload: %w", err)
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, c.baseURL()+"/teams/"+url.PathEscape(teamID), body)
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
		return fmt.Errorf("intercom: team PUT status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ProvisionAccess adds an admin to a Team via PUT /teams/{teamId}
// with the union of current admin_ids and the new id. No-op if the admin
// is already a member.
func (c *IntercomAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("intercom: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("intercom: grant.ResourceExternalID (teamId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	team, err := c.getTeam(ctx, secrets, grant.ResourceExternalID)
	if err != nil {
		return err
	}
	if team == nil {
		return fmt.Errorf("intercom: team %s not found", grant.ResourceExternalID)
	}
	for _, a := range team.AdminIDs {
		if a == grant.UserExternalID {
			return nil
		}
	}
	// Build the admins slice by explicit copy rather than append to
	// avoid mutating the underlying array of team.AdminIDs. The
	// previous `append(team.AdminIDs, ...)` was safe today only
	// because getTeam() returns a fresh slice per call; an explicit
	// copy makes the contract independent of that detail.
	admins := make([]string, len(team.AdminIDs), len(team.AdminIDs)+1)
	copy(admins, team.AdminIDs)
	admins = append(admins, grant.UserExternalID)
	return c.putTeamAdmins(ctx, secrets, grant.ResourceExternalID, admins)
}

// RevokeAccess removes an admin from a Team via PUT /teams/{teamId}
// with the admin filtered out. Missing team ⇒ idempotent success.
func (c *IntercomAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("intercom: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("intercom: grant.ResourceExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	team, err := c.getTeam(ctx, secrets, grant.ResourceExternalID)
	if err != nil {
		return err
	}
	if team == nil {
		return nil
	}
	found := false
	admins := make([]string, 0, len(team.AdminIDs))
	for _, a := range team.AdminIDs {
		if a == grant.UserExternalID {
			found = true
			continue
		}
		admins = append(admins, a)
	}
	if !found {
		return nil
	}
	return c.putTeamAdmins(ctx, secrets, grant.ResourceExternalID, admins)
}

// ListEntitlements walks /teams and emits one Entitlement per team that
// has the user as an admin member.
func (c *IntercomAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("intercom: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/teams")
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp intercomTeamsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("intercom: decode teams: %w", err)
	}
	var out []access.Entitlement
	for _, tm := range resp.Teams {
		for _, a := range tm.AdminIDs {
			if a == userExternalID {
				out = append(out, access.Entitlement{
					ResourceExternalID: tm.ID,
					Role:               "member",
					Source:             "direct",
				})
				break
			}
		}
	}
	return out, nil
}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// Intercom workspace. Intercom supports SAML 2.0 SSO for Premium plans
// via the admin Authentication settings; the connector forwards
// operator-supplied URLs verbatim via access.SSOMetadataFromConfig so the
// SSOFederationService can register a iam-core SAML broker. Returns
// (nil, nil) when the operator has not supplied a metadata URL so the
// caller downgrades gracefully.
func (c *IntercomAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *IntercomAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*IntercomAccessConnector)(nil)
