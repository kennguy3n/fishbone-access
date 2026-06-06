// Package wasabi implements the access.AccessConnector contract for the
// Wasabi IAM-compatible ListUsers API.
package wasabi

import (
	"context"
	"encoding/xml"
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
	ProviderName   = "wasabi"
	defaultBaseURL = "https://iam.wasabisys.com/"
	defaultRegion  = "us-east-1"
	iamAPIVersion  = "2010-05-08"
)

var ErrNotImplemented = fmt.Errorf("wasabi: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

type WasabiAccessConnector struct {
	httpClient   func() httpDoer
	urlOverride  string
	timeOverride func() time.Time
}

func New() *WasabiAccessConnector { return &WasabiAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("wasabi: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("wasabi: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_key_id"].(string); ok {
		s.AccessKeyID = v
	}
	if v, ok := raw["secret_access_key"].(string); ok {
		s.SecretAccessKey = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessKeyID) == "" {
		return errors.New("wasabi: access_key_id is required")
	}
	if strings.TrimSpace(s.SecretAccessKey) == "" {
		return errors.New("wasabi: secret_access_key is required")
	}
	return nil
}

func (c *WasabiAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *WasabiAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return defaultBaseURL
}

func (c *WasabiAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *WasabiAccessConnector) now() time.Time {
	if c.timeOverride != nil {
		return c.timeOverride()
	}
	return time.Now()
}

func (c *WasabiAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *WasabiAccessConnector) callIAM(ctx context.Context, secrets Secrets, params url.Values) ([]byte, error) {
	if params.Get("Version") == "" {
		params.Set("Version", iamAPIVersion)
	}
	body := params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/xml")
	if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, defaultRegion, "iam", c.now()); err != nil {
		return nil, fmt.Errorf("wasabi: sign: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("wasabi: %s: network error", params.Get("Action"))
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wasabi: %s: status %d: %s", params.Get("Action"), resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func (c *WasabiAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("Action", "ListUsers")
	params.Set("MaxItems", "1")
	if _, err := c.callIAM(ctx, secrets, params); err != nil {
		return fmt.Errorf("wasabi: connect probe: %w", err)
	}
	return nil
}

func (c *WasabiAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type listUsersResponse struct {
	XMLName         xml.Name `xml:"ListUsersResponse"`
	ListUsersResult struct {
		IsTruncated bool   `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Users       []struct {
			UserName   string `xml:"UserName"`
			UserID     string `xml:"UserId"`
			Arn        string `xml:"Arn"`
			Path       string `xml:"Path"`
			CreateDate string `xml:"CreateDate"`
		} `xml:"Users>member"`
	} `xml:"ListUsersResult"`
}

func (c *WasabiAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *WasabiAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	marker := checkpoint
	for {
		params := url.Values{}
		params.Set("Action", "ListUsers")
		params.Set("MaxItems", "100")
		if marker != "" {
			params.Set("Marker", marker)
		}
		body, err := c.callIAM(ctx, secrets, params)
		if err != nil {
			return err
		}
		var resp listUsersResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("wasabi: decode ListUsers: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.ListUsersResult.Users))
		for _, u := range resp.ListUsersResult.Users {
			identities = append(identities, &access.Identity{
				ExternalID:  u.UserID,
				Type:        access.IdentityTypeUser,
				DisplayName: u.UserName,
				Status:      "active",
				RawData:     map[string]interface{}{"arn": u.Arn, "path": u.Path, "create_date": u.CreateDate},
			})
		}
		next := ""
		if resp.ListUsersResult.IsTruncated {
			next = resp.ListUsersResult.Marker
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		marker = next
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Wasabi
// console SSO federation. When `sso_metadata_url` is blank the helper
// returns (nil, nil) and the caller gracefully downgrades.
func (c *WasabiAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *WasabiAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":            ProviderName,
		"auth_type":           "iam_access_key",
		"access_key_id_short": shortToken(secrets.AccessKeyID),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*WasabiAccessConnector)(nil)
