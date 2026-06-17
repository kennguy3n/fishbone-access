// Package qualys implements the access.AccessConnector contract for the
// Qualys VMDR /api/2.0/fo/user/ endpoint.
//
// Qualys is region-routed: the API host depends on the customer's
// platform (US-1/2/3, EU-1/2, IN-1, AE-1, UK-1, CA-1, AU-1). The
// connector accepts either a `platform` short code (preferred) or a
// fully-qualified `base_url`. The `base_url` validator follows the
// Travis CI pattern: HTTPS only, no IP literals, no userinfo, no path /
// query / fragment, DNS-shaped host. Qualys requires HTTP Basic auth
// and an `X-Requested-With` header on every request.
package qualys

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "qualys"
	pageSize     = 100
)

// platformHosts maps Qualys platform short codes to their published API
// hosts. Restricting the connector to this allow-list (or a validated
// custom https URL) prevents an attacker who controls config from
// pointing the connector at an arbitrary destination.
var platformHosts = map[string]string{
	"us1": "https://qualysapi.qualys.com",
	"us2": "https://qualysapi.qg2.apps.qualys.com",
	"us3": "https://qualysapi.qg3.apps.qualys.com",
	"us4": "https://qualysapi.qg4.apps.qualys.com",
	"eu1": "https://qualysapi.qualys.eu",
	"eu2": "https://qualysapi.qg2.apps.qualys.eu",
	"in1": "https://qualysapi.qg1.apps.qualys.in",
	"ae1": "https://qualysapi.qg1.apps.qualys.ae",
	"uk1": "https://qualysapi.qg1.apps.qualys.co.uk",
	"ca1": "https://qualysapi.qg1.apps.qualys.ca",
	"au1": "https://qualysapi.qg1.apps.qualys.com.au",
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	// Platform is a short code such as "us1", "eu1", or "in1". When
	// non-empty it selects a host from the published platformHosts
	// allow-list and BaseURL must be empty.
	Platform string `json:"platform"`
	// BaseURL is an explicit https URL for operators on dedicated
	// platforms. Mutually exclusive with Platform.
	BaseURL string `json:"base_url"`
}

type Secrets struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type QualysAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *QualysAccessConnector { return &QualysAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("qualys: config is nil")
	}
	var cfg Config
	if v, ok := raw["platform"].(string); ok {
		cfg.Platform = v
	}
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("qualys: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["username"].(string); ok {
		s.Username = v
	}
	if v, ok := raw["password"].(string); ok {
		s.Password = v
	}
	return s, nil
}

func (c Config) validate() error {
	platform := strings.TrimSpace(strings.ToLower(c.Platform))
	base := strings.TrimSpace(c.BaseURL)
	if platform == "" && base == "" {
		return errors.New("qualys: one of platform or base_url is required")
	}
	if platform != "" && base != "" {
		return errors.New("qualys: platform and base_url are mutually exclusive")
	}
	if platform != "" {
		if _, ok := platformHosts[platform]; !ok {
			return fmt.Errorf("qualys: unknown platform %q (allowed: us1, us2, us3, us4, eu1, eu2, in1, ae1, uk1, ca1, au1)", platform)
		}
		return nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("qualys: base_url must be a well-formed URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("qualys: base_url must use https://")
	}
	if u.User != nil {
		return errors.New("qualys: base_url must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("qualys: base_url must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("qualys: base_url must not contain a query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("qualys: base_url must contain a host")
	}
	if net.ParseIP(host) != nil {
		return errors.New("qualys: base_url host must be a domain name, not an IP literal")
	}
	if !isHost(host) {
		return errors.New("qualys: base_url host must contain only DNS label characters and dots")
	}
	return nil
}

func isHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Username) == "" {
		return errors.New("qualys: username is required")
	}
	if strings.TrimSpace(s.Password) == "" {
		return errors.New("qualys: password is required")
	}
	return nil
}

func (c *QualysAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *QualysAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	if base := strings.TrimSpace(cfg.BaseURL); base != "" {
		return strings.TrimRight(base, "/")
	}
	return platformHosts[strings.TrimSpace(strings.ToLower(cfg.Platform))]
}

func (c *QualysAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *QualysAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	// Qualys VMDR returns XML by default and requires X-Requested-With
	// to defeat CSRF on session-style auth. We accept XML and decode
	// the documented USER_LIST_OUTPUT envelope.
	req.Header.Set("Accept", "application/xml")
	req.Header.Set("X-Requested-With", "shieldnet360-access")
	creds := strings.TrimSpace(secrets.Username) + ":" + strings.TrimSpace(secrets.Password)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *QualysAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("qualys: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("qualys: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *QualysAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *QualysAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/api/2.0/fo/user/?action=list&truncation_limit=1"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("qualys: connect probe: %w", err)
	}
	return nil
}

func (c *QualysAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

// USER_LIST_OUTPUT envelope (subset we care about).
type qualysUserList struct {
	XMLName  xml.Name `xml:"USER_LIST_OUTPUT"`
	Response struct {
		UserList struct {
			Users []qualysUser `xml:"USER"`
		} `xml:"USER_LIST"`
	} `xml:"RESPONSE"`
}

type qualysUser struct {
	UserLogin string `xml:"USER_LOGIN"`
	UserID    string `xml:"USER_ID"`
	UserRole  string `xml:"USER_ROLE"`
	FirstName string `xml:"FIRST_NAME"`
	LastName  string `xml:"LAST_NAME"`
	Email     string `xml:"EMAIL"`
	Status    string `xml:"USER_STATUS"`
}

func (c *QualysAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *QualysAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	idMin := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &idMin)
		if idMin < 0 {
			idMin = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		q := url.Values{
			"action":           []string{"list"},
			"truncation_limit": []string{fmt.Sprintf("%d", pageSize)},
		}
		if idMin > 0 {
			q.Set("id_min", fmt.Sprintf("%d", idMin))
		}
		fullURL := base + "/api/2.0/fo/user/?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp qualysUserList
		if err := xml.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("qualys: decode users xml: %w", err)
		}
		users := resp.Response.UserList.Users
		identities := make([]*access.Identity, 0, len(users))
		maxID := idMin
		for _, u := range users {
			external := strings.TrimSpace(u.UserID)
			if external == "" {
				external = strings.TrimSpace(u.UserLogin)
			}
			display := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
			if display == "" {
				display = strings.TrimSpace(u.UserLogin)
			}
			status := "active"
			switch strings.ToLower(strings.TrimSpace(u.Status)) {
			case "disabled", "inactive":
				status = "disabled"
			case "pending":
				status = "pending"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  external,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       strings.TrimSpace(u.Email),
				Status:      status,
			})
			// Qualys VMDR USER_IDs are numeric integers per the public API
			// spec; non-numeric values are skipped explicitly so the cursor
			// only advances on confirmed progress. Combined with the
			// `maxID > idMin` guard below, an entire unparseable page would
			// terminate the sync rather than loop forever.
			if id, err := strconv.Atoi(strings.TrimSpace(u.UserID)); err == nil && id > maxID {
				maxID = id
			}
		}
		next := ""
		if len(users) == pageSize && maxID > idMin {
			next = fmt.Sprintf("%d", maxID+1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		idMin = maxID + 1
	}
}

// GetSSOMetadata projects the connector's configured `sso_metadata_url` /
// `sso_entity_id` into the shared SAML envelope used to broker Qualys
// VMDR / Cloud Platform SSO federation. When `sso_metadata_url` is blank
// the helper returns (nil, nil) and the caller gracefully downgrades.
func (c *QualysAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *QualysAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	platform := strings.TrimSpace(strings.ToLower(cfg.Platform))
	if platform == "" && cfg.BaseURL != "" {
		platform = "custom"
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"auth_type":      "basic",
		"platform":       platform,
		"username_short": shortToken(secrets.Username),
		"password_short": shortToken(secrets.Password),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*QualysAccessConnector)(nil)
