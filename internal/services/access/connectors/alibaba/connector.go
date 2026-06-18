// Package alibaba implements the access.AccessConnector contract for the
// Alibaba Cloud RAM ListUsers API.
package alibaba

import (
	"context"
	"crypto/hmac"
	// gosec G505 false positive: Alibaba Cloud RAM's Open API
	// signing protocol mandates HMAC-SHA1. This is a protocol
	// requirement, not a cryptographic strength choice.
	"crypto/sha1" // #nosec G505
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName       = "alibaba"
	defaultBaseURL     = "https://ram.aliyuncs.com/"
	ramAPIVersion      = "2015-05-01"
	signatureMethod    = "HMAC-SHA1"
	signatureVersion   = "1.0"
	signatureAlgorithm = signatureMethod
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
}

type AlibabaAccessConnector struct {
	httpClient    func() httpDoer
	urlOverride   string
	timeOverride  func() time.Time
	nonceOverride func() string
}

func New() *AlibabaAccessConnector { return &AlibabaAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("alibaba: config is nil")
	}
	return Config{}, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("alibaba: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_key_id"].(string); ok {
		s.AccessKeyID = v
	}
	if v, ok := raw["access_key_secret"].(string); ok {
		s.AccessKeySecret = v
	}
	return s, nil
}

func (Config) validate() error { return nil }

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessKeyID) == "" {
		return errors.New("alibaba: access_key_id is required")
	}
	if strings.TrimSpace(s.AccessKeySecret) == "" {
		return errors.New("alibaba: access_key_secret is required")
	}
	return nil
}

func (c *AlibabaAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *AlibabaAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return defaultBaseURL
}

func (c *AlibabaAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *AlibabaAccessConnector) now() time.Time {
	if c.timeOverride != nil {
		return c.timeOverride()
	}
	return time.Now()
}

func (c *AlibabaAccessConnector) nonce() string {
	if c.nonceOverride != nil {
		return c.nonceOverride()
	}
	return fmt.Sprintf("%d", c.now().UnixNano())
}

// percentEncode encodes per the Alibaba Cloud signature spec (RFC 3986),
// then replaces '+' with %20, '*' with %2A, and %7E with '~'.
func percentEncode(s string) string {
	enc := url.QueryEscape(s)
	enc = strings.ReplaceAll(enc, "+", "%20")
	enc = strings.ReplaceAll(enc, "*", "%2A")
	enc = strings.ReplaceAll(enc, "%7E", "~")
	return enc
}

func sign(secret string, params map[string]string, method string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteString("&")
		}
		canonical.WriteString(percentEncode(k))
		canonical.WriteString("=")
		canonical.WriteString(percentEncode(params[k]))
	}
	stringToSign := method + "&" + percentEncode("/") + "&" + percentEncode(canonical.String())
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (c *AlibabaAccessConnector) callRAM(ctx context.Context, secrets Secrets, action string, extra map[string]string) ([]byte, error) {
	params := map[string]string{
		"Format":           "JSON",
		"Version":          ramAPIVersion,
		"AccessKeyId":      strings.TrimSpace(secrets.AccessKeyID),
		"SignatureMethod":  signatureMethod,
		"Timestamp":        c.now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": signatureVersion,
		"SignatureNonce":   c.nonce(),
		"Action":           action,
	}
	for k, v := range extra {
		params[k] = v
	}
	signature := sign(strings.TrimSpace(secrets.AccessKeySecret), params, http.MethodGet)
	params["Signature"] = signature

	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	full := c.baseURL() + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		// Avoid leaking signed URL in errors.
		return nil, fmt.Errorf("alibaba: %s: network error", action)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("alibaba: %s: status %d: %s", action, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *AlibabaAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *AlibabaAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.callRAM(ctx, secrets, "ListUsers", map[string]string{"MaxItems": "1"}); err != nil {
		return fmt.Errorf("alibaba: connect probe: %w", err)
	}
	return nil
}

func (c *AlibabaAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type ramUser struct {
	UserID      string `json:"UserId"`
	UserName    string `json:"UserName"`
	DisplayName string `json:"DisplayName"`
	Email       string `json:"Email"`
}

type listUsersResponse struct {
	IsTruncated bool   `json:"IsTruncated"`
	Marker      string `json:"Marker"`
	Users       struct {
		User []ramUser `json:"User"`
	} `json:"Users"`
}

func (c *AlibabaAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *AlibabaAccessConnector) SyncIdentities(
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
		extra := map[string]string{"MaxItems": "100"}
		if marker != "" {
			extra["Marker"] = marker
		}
		body, err := c.callRAM(ctx, secrets, "ListUsers", extra)
		if err != nil {
			return err
		}
		var resp listUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("alibaba: decode ListUsers: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Users.User))
		for _, u := range resp.Users.User {
			display := u.DisplayName
			if display == "" {
				display = u.UserName
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.UserID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       u.Email,
				Status:      "active",
			})
		}
		next := ""
		if resp.IsTruncated {
			next = resp.Marker
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

// Alibaba SSO federation. When `sso_metadata_url` is blank the helper returns
// (nil, nil) and the caller gracefully downgrades.
func (c *AlibabaAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *AlibabaAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":            ProviderName,
		"auth_type":           "ram_access_key",
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

var _ access.AccessConnector = (*AlibabaAccessConnector)(nil)
