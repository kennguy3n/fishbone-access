// Package front implements the access.AccessConnector contract for the
// Front /teammates API.
package front

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

const ProviderName = "front"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type FrontAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *FrontAccessConnector { return &FrontAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("front: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("front: secrets is nil")
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
		return errors.New("front: token is required")
	}
	return nil
}

func (c *FrontAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *FrontAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api2.frontapp.com"
}

func (c *FrontAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *FrontAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *FrontAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *FrontAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("front: %s %s: %w", req.Method, req.URL.Path, err)
	}
	return resp, nil
}

func (c *FrontAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("front: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("front: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

// do2xxOr404 is do() with the special case that a 404 response is
// treated as a terminal "not found" rather than an error. Callers
// that need to distinguish "gone" from "failed" use this so the
// leaver-flow contract (404 -> empty membership) is centralised
// alongside the rest of the HTTP plumbing. found is false on 404.
func (c *FrontAccessConnector) do2xxOr404(req *http.Request) (body []byte, found bool, err error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("front: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return buf, true, nil
	default:
		return nil, false, fmt.Errorf("front: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(buf))
	}
}

func (c *FrontAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *FrontAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/teammates"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("front: connect probe: %w", err)
	}
	return nil
}

func (c *FrontAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type frontTeammate struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	IsAvailable bool   `json:"is_available"`
	IsBlocked   bool   `json:"is_blocked"`
}

type frontListResponse struct {
	Pagination frontPagination `json:"_pagination"`
	Results    []frontTeammate `json:"_results"`
}

func (c *FrontAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *FrontAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	url := checkpoint
	if url == "" {
		url = c.baseURL() + "/teammates"
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp frontListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("front: decode teammates: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Results))
		for _, t := range resp.Results {
			display := strings.TrimSpace(t.FirstName + " " + t.LastName)
			if display == "" {
				display = t.Username
			}
			if display == "" {
				display = t.Email
			}
			status := "active"
			if t.IsBlocked {
				status = "blocked"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  t.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       t.Email,
				Status:      status,
			})
		}
		nextCursor := strings.TrimSpace(resp.Pagination.Next)
		if err := handler(identities, nextCursor); err != nil {
			return err
		}
		if nextCursor == "" {
			return nil
		}
		url = nextCursor
	}
}

// ---------- advanced capabilities ----------

type frontTeam struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// frontTeamsResponse mirrors the envelope returned by /teams. The
// JSON tag on the second field is `_pagination` to match Front's
// API, and the Go field is named `Pagination` so the in-package
// idiom is uniform with frontListResponse (also `Pagination`) and
// audit.go. Earlier versions used `Links`, which forced readers to
// mentally map two Go names to the same JSON path.
type frontTeamsResponse struct {
	Results    []frontTeam     `json:"_results"`
	Pagination frontPagination `json:"_pagination"`
}

// frontPagination is the shared `_pagination` envelope reused by
// every Front list response. Centralising it removes the inline
// `struct{ Next string }` definitions that previously appeared on
// frontTeamsResponse and frontListResponse and makes future
// additions to the pagination payload (cursors, totals) a single-
// site edit.
type frontPagination struct {
	Next string `json:"next"`
}

// ProvisionAccess adds a teammate to a team via
// POST /teams/{teamId}/teammates with {"teammate_ids":[id]}. 409 maps to
// idempotent success.
func (c *FrontAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("front: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("front: grant.ResourceExternalID (teamId) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{"teammate_ids": []string{grant.UserExternalID}}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("front: marshal payload: %w", err)
	}
	fullURL := c.baseURL() + "/teams/" + url.PathEscape(grant.ResourceExternalID) + "/teammates"
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
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return nil
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(bytes.ToLower(respBody), []byte("already")):
		return nil
	default:
		return fmt.Errorf("front: teammate POST status %d: %s", resp.StatusCode, string(respBody))
	}
}

// RevokeAccess removes a teammate from a team via
// DELETE /teams/{teamId}/teammates with {"teammate_ids":[id]}. 404 ⇒ idempotent.
func (c *FrontAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if strings.TrimSpace(grant.UserExternalID) == "" {
		return errors.New("front: grant.UserExternalID is required")
	}
	if strings.TrimSpace(grant.ResourceExternalID) == "" {
		return errors.New("front: grant.ResourceExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{"teammate_ids": []string{grant.UserExternalID}}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("front: marshal payload: %w", err)
	}
	fullURL := c.baseURL() + "/teams/" + url.PathEscape(grant.ResourceExternalID) + "/teammates"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, fullURL, body)
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
		return fmt.Errorf("front: teammate DELETE status %d: %s", resp.StatusCode, string(respBody))
	}
}

// ListEntitlements walks /teammates/{id}/teams and emits one Entitlement
// per team.
func (c *FrontAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return nil, errors.New("front: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	next := c.baseURL() + "/teammates/" + url.PathEscape(userExternalID) + "/teams"
	var out []access.Entitlement
	for next != "" {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, next)
		if err != nil {
			return nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return nil, err
		}
		var resp frontTeamsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("front: decode teams: %w", err)
		}
		for _, tm := range resp.Results {
			out = append(out, access.Entitlement{
				ResourceExternalID: tm.ID,
				Role:               "teammate",
				Source:             "direct",
			})
		}
		next = strings.TrimSpace(resp.Pagination.Next)
	}
	return out, nil
}
func (c *FrontAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *FrontAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*FrontAccessConnector)(nil)
