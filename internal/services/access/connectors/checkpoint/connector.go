// Package checkpoint implements the access.AccessConnector contract for the
// Check Point /web_api/show-administrators API.
package checkpoint

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
	ProviderName = "checkpoint"
	pageSize     = 100
)

// The ErrNotImplemented sentinel was retired when
// ProvisionAccess / RevokeAccess / ListEntitlements gained real
// implementations against /web_api/{add,delete,show}-administrator (see
// advanced.go). Tests now assert the real success/error paths against an
// httptest fake of the Check Point Management API.

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	Token string `json:"token"`
}

type CheckPointAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *CheckPointAccessConnector { return &CheckPointAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("checkpoint: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("checkpoint: secrets is nil")
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
		return errors.New("checkpoint: token is required")
	}
	return nil
}

func (c *CheckPointAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *CheckPointAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://api.checkpoint.com"
}

func (c *CheckPointAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *CheckPointAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-chkp-sid", strings.TrimSpace(secrets.Token))
	return req, nil
}

// newPostJSON builds a Check Point Management API call. The /web_api/*
// endpoints are POST-only and accept their parameters in a JSON body,
// not as URL query params.
func (c *CheckPointAccessConnector) newPostJSON(ctx context.Context, secrets Secrets, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-chkp-sid", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *CheckPointAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("checkpoint: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *CheckPointAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *CheckPointAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{
		"details-level": "standard",
		"offset":        0,
		"limit":         1,
	})
	req, err := c.newPostJSON(ctx, secrets, c.baseURL()+"/web_api/show-administrators", body)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("checkpoint: connect probe: %w", err)
	}
	return nil
}

func (c *CheckPointAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

// checkpointUser mirrors the per-administrator payload returned by the
// Check Point Management API `show-administrators` endpoint. The endpoint
// does not expose a per-admin enable/disable flag in its standard response
// (`locked` is not part of the documented administrator object), so identity
// status defaults to "active" for any administrator returned.
type checkpointUser struct {
	ID    string `json:"uid"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type checkpointListResponse struct {
	Items []checkpointUser `json:"objects"`
}

func (c *CheckPointAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *CheckPointAccessConnector) SyncIdentities(
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
	base := c.baseURL()
	for {
		reqBody, _ := json.Marshal(map[string]interface{}{
			"details-level": "standard",
			"offset":        offset,
			"limit":         pageSize,
		})
		req, err := c.newPostJSON(ctx, secrets, base+"/web_api/show-administrators", reqBody)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp checkpointListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("checkpoint: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Items))
		for _, u := range resp.Items {
			display := strings.TrimSpace(u.Name)
			if display == "" {
				display = u.Email
			}
			// Identity.ExternalID is intentionally the administrator
			// `name` (the only field the Check Point Management API
			// /web_api/{add,delete,show}-administrator verbs accept as
			// the addressable key for an administrator). The opaque
			// session-scoped `uid` is preserved in RawData["uid"] for
			// downstream consumers that index by it. This is a
			// deliberate contract decision rather than a regression:
			// surfacing `uid` here would make Identity.ExternalID
			// values unusable as AccessGrant.UserExternalID, breaking
			// the Provision/Revoke/ListEntitlements contract documented
			// in advanced.go.
			external := strings.TrimSpace(u.Name)
			if external == "" {
				external = strings.TrimSpace(u.ID)
			}
			raw := map[string]interface{}{}
			if v := strings.TrimSpace(u.ID); v != "" {
				raw["uid"] = v
			}
			identities = append(identities, &access.Identity{
				ExternalID:  external,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
				RawData:     raw,
			})
		}
		next := ""
		if len(resp.Items) == pageSize {
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

func (c *CheckPointAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *CheckPointAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "api_key",
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

var _ access.AccessConnector = (*CheckPointAccessConnector)(nil)
