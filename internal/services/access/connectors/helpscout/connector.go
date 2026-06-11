// Package helpscout implements the access.AccessConnector contract for the
// Help Scout users API.
package helpscout

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
	ProviderName   = "helpscout"
	defaultBaseURL = "https://api.helpscout.net/v2"
	pageSize       = 50
)

var ErrNotImplemented = fmt.Errorf("helpscout: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type HelpScoutAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *HelpScoutAccessConnector { return &HelpScoutAccessConnector{} }
func init()                          { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(_ map[string]interface{}) (Config, error) { return Config{}, nil }

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("helpscout: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("helpscout: access_token is required")
	}
	return nil
}

func (c *HelpScoutAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	if _, err := DecodeConfig(configRaw); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *HelpScoutAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *HelpScoutAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *HelpScoutAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *HelpScoutAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *HelpScoutAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("helpscout: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *HelpScoutAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("helpscout: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("helpscout: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *HelpScoutAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
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

func (c *HelpScoutAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/users?size=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("helpscout: connect probe: %w", err)
	}
	return nil
}

func (c *HelpScoutAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type helpscoutUsersResponse struct {
	Embedded struct {
		Users []helpscoutUser `json:"users"`
	} `json:"_embedded"`
	Page struct {
		Size          int `json:"size"`
		TotalElements int `json:"totalElements"`
		TotalPages    int `json:"totalPages"`
		Number        int `json:"number"`
	} `json:"page"`
}

type helpscoutUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Type      string `json:"type"`
}

func (c *HelpScoutAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *HelpScoutAccessConnector) SyncIdentities(
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
	for {
		path := fmt.Sprintf("/users?page=%d&size=%d", page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp helpscoutUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("helpscout: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Embedded.Users))
		for _, u := range resp.Embedded.Users {
			idType := access.IdentityTypeUser
			if strings.EqualFold(u.Type, "team") || strings.EqualFold(u.Type, "service") {
				idType = access.IdentityTypeServiceAccount
			}
			display := strings.TrimSpace(u.FirstName + " " + u.LastName)
			if display == "" {
				display = u.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", u.ID),
				Type:        idType,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if resp.Page.TotalPages > page {
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

type helpscoutTeamMember struct {
	ID int64 `json:"id"`
}

type helpscoutTeam struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type helpscoutTeamsResponse struct {
	Embedded struct {
		Teams []helpscoutTeam `json:"teams"`
	} `json:"_embedded"`
	Page struct {
		Size          int `json:"size"`
		TotalElements int `json:"totalElements"`
		TotalPages    int `json:"totalPages"`
		Number        int `json:"number"`
	} `json:"page"`
}

type helpscoutTeamMembersResponse struct {
	Embedded struct {
		Users []helpscoutUser `json:"users"`
	} `json:"_embedded"`
	Page struct {
		Size          int `json:"size"`
		TotalElements int `json:"totalElements"`
		TotalPages    int `json:"totalPages"`
		Number        int `json:"number"`
	} `json:"page"`
}

// ProvisionAccess assigns a user to a Help Scout Team via
// PUT /teams/{teamId}/members/{userId}. 409 (already member) maps to
// idempotent success.
func (c *HelpScoutAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("helpscout: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("helpscout: grant.ResourceExternalID (teamId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := "/teams/" + url.PathEscape(grant.ResourceExternalID) + "/members/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, path, []byte(`{}`))
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
		return fmt.Errorf("helpscout: team member PUT status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a user from a Team via
// DELETE /teams/{teamId}/members/{userId}. 404 ⇒ idempotent success.
func (c *HelpScoutAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("helpscout: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("helpscout: grant.ResourceExternalID (teamId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := "/teams/" + url.PathEscape(grant.ResourceExternalID) + "/members/" + url.PathEscape(grant.UserExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, path)
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
		return fmt.Errorf("helpscout: team member DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements pages /teams and, for each team, resolves membership by
// paging that team's /teams/{teamId}/members list. Each team containing the
// user produces one Entitlement. A transport or decode failure encountered
// while enumerating teams or members is propagated rather than returning a
// partial list, so a transient error can never silently under-report a user's
// access.
func (c *HelpScoutAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("helpscout: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var out []access.Entitlement
	page := 1
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fmt.Sprintf("/teams?page=%d&size=%d", page, pageSize))
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp helpscoutTeamsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("helpscout: decode teams: %w", err)
		}
		for _, tm := range resp.Embedded.Teams {
			isMember, err := c.userInTeam(ctx, secrets, tm.ID, userExternalID)
			if err != nil {
				return nil, err
			}
			if isMember {
				out = append(out, access.Entitlement{
					ResourceExternalID: strconv.FormatInt(tm.ID, 10),
					Role:               "member",
					Source:             "direct",
				})
			}
		}
		if resp.Page.TotalPages == 0 || resp.Page.Number >= resp.Page.TotalPages {
			return out, nil
		}
		page = resp.Page.Number + 1
	}
}

// userInTeam reports whether userExternalID belongs to teamID by paging the
// team's member list (GET /teams/{teamId}/members) and matching on the numeric
// Help Scout user id. It returns as soon as the user is found, so a hit costs at
// most one page rather than the whole roster.
//
// Help Scout's Mailbox API exposes team membership only through this listing
// endpoint — there is no documented GET on an individual member resource — so
// resolving membership is inherently a scan of the team's members. The match is
// kept strictly on the numeric id that ProvisionAccess / RevokeAccess use as a
// path segment and that SyncIdentities emits, so any reported entitlement is
// revocable with the same UserExternalID. A 404 means the team (or its member
// collection) is absent ⇒ not a member; any other non-2xx, a read failure, or a
// malformed body is propagated rather than being treated as "no membership".
func (c *HelpScoutAccessConnector) userInTeam(ctx context.Context, secrets Secrets, teamID int64, userExternalID string) (bool, error) {
	page := 1
	for {
		path := fmt.Sprintf("/teams/%d/members?page=%d&size=%d", teamID, page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return false, err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return false, err
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		if readErr != nil {
			return false, fmt.Errorf("helpscout: read team members: %w", readErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, fmt.Errorf("helpscout: team members GET status %d: %s", resp.StatusCode, string(body))
		}
		var members helpscoutTeamMembersResponse
		if err := json.Unmarshal(body, &members); err != nil {
			return false, fmt.Errorf("helpscout: decode team members: %w", err)
		}
		for _, u := range members.Embedded.Users {
			if strconv.FormatInt(u.ID, 10) == userExternalID {
				return true, nil
			}
		}
		if members.Page.TotalPages == 0 || members.Page.Number >= members.Page.TotalPages {
			return false, nil
		}
		page = members.Page.Number + 1
	}
}

var _ = helpscoutTeamMember{}

// GetSSOMetadata surfaces operator-supplied SAML metadata for the
// HelpScout workspace. HelpScout Plus supports SAML 2.0 SSO with
// metadata hosted by the customer's IdP; the connector forwards
// operator-supplied URLs verbatim via access.SSOMetadataFromConfig so
// the SSOFederationService can register a iam-core SAML broker. Returns
// (nil, nil) when the operator has not supplied a metadata URL so the
// caller downgrades gracefully.
func (c *HelpScoutAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *HelpScoutAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "oauth_access_token",
		"token_short": shortToken(s.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*HelpScoutAccessConnector)(nil)
