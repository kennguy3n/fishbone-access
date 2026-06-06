// Package dropbox implements the access.AccessConnector contract for the
// Dropbox Business team members API.
package dropbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "dropbox"
	pageSize     = 100
)

var ErrNotImplemented = fmt.Errorf("dropbox: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type DropboxAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *DropboxAccessConnector { return &DropboxAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("dropbox: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("dropbox: secrets is nil")
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
		return errors.New("dropbox: access_token is required")
	}
	return nil
}

func (c *DropboxAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DropboxAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.dropboxapi.com"
}

func (c *DropboxAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *DropboxAccessConnector) postJSON(ctx context.Context, secrets Secrets, fullURL string, payload interface{}) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("dropbox: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("dropbox: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dropbox: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func (c *DropboxAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *DropboxAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/2/team/get_info"
	if _, err := c.postJSON(ctx, secrets, probe, struct{}{}); err != nil {
		return fmt.Errorf("dropbox: connect probe: %w", err)
	}
	return nil
}

func (c *DropboxAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type dropboxProfile struct {
	TeamMemberID string `json:"team_member_id"`
	Email        string `json:"email"`
	Status       struct {
		Tag string `json:".tag"`
	} `json:"status"`
	Name struct {
		DisplayName string `json:"display_name"`
		GivenName   string `json:"given_name"`
		Surname     string `json:"surname"`
	} `json:"name"`
}

type dropboxMember struct {
	Profile dropboxProfile `json:"profile"`
}

type dropboxListResponse struct {
	Members []dropboxMember `json:"members"`
	Cursor  string          `json:"cursor"`
	HasMore bool            `json:"has_more"`
}

func (c *DropboxAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *DropboxAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	base := c.baseURL()
	for {
		var url string
		var payload interface{}
		if cursor == "" {
			url = base + "/2/team/members/list_v2"
			payload = map[string]interface{}{"limit": pageSize, "include_removed": true}
		} else {
			url = base + "/2/team/members/list/continue_v2"
			payload = map[string]interface{}{"cursor": cursor}
		}
		body, err := c.postJSON(ctx, secrets, url, payload)
		if err != nil {
			return err
		}
		var resp dropboxListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("dropbox: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Members))
		for _, m := range resp.Members {
			display := m.Profile.Name.DisplayName
			if display == "" {
				display = strings.TrimSpace(m.Profile.Name.GivenName + " " + m.Profile.Name.Surname)
			}
			if display == "" {
				display = m.Profile.Email
			}
			status := strings.ToLower(m.Profile.Status.Tag)
			if status == "" {
				status = "active"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.Profile.TeamMemberID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Profile.Email,
				Status:      status,
			})
		}
		next := ""
		if resp.HasMore {
			next = resp.Cursor
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

func (c *DropboxAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("dropbox: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{".tag": "team_member_id", "team_member_id": grant.UserExternalID, "new_role": grant.ResourceExternalID})
	urlStr := c.baseURL() + "/2/team/members/set_permissions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("dropbox: provision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("dropbox: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *DropboxAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("dropbox: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{".tag": "team_member_id", "team_member_id": grant.UserExternalID})
	urlStr := c.baseURL() + "/2/team/members/remove"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("dropbox: revoke: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if strings.Contains(string(respBody), "user_not_found") || strings.Contains(string(respBody), "user_not_in_team") {
		return nil
	}
	return fmt.Errorf("dropbox: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *DropboxAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("dropbox: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	payload := map[string]interface{}{".tag": "team_member_id", "team_member_id": userExternalID}
	respBody, err := c.postJSON(ctx, secrets, c.baseURL()+"/2/team/members/get_info_v2", payload)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Role struct {
			Tag string `json:".tag"`
		} `json:"role"`
	}
	if json.Unmarshal(respBody, &resp) != nil {
		return nil, nil
	}
	if resp.Role.Tag == "" {
		return nil, nil
	}
	return []access.Entitlement{{ResourceExternalID: "team", Role: resp.Role.Tag, Source: "direct"}}, nil
}

func (c *DropboxAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.dropbox.com/saml_login/metadata",
		EntityID:    "https://www.dropbox.com",
	}, nil
}

func (c *DropboxAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*DropboxAccessConnector)(nil)
