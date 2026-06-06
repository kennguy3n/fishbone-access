// Package splunk implements the access.AccessConnector contract for the
// Splunk Cloud /services/authentication/users API.
package splunk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ProviderName = "splunk"
	pageSize     = 100
)

// splunkIdentitiesMaxPages caps the per-call page walk in
// SyncIdentities (and the CountIdentities-via-SyncIdentities path).
// Even with an aggressively oversized Splunk org (100k+ users at
// pageSize=100), legitimate pagination terminates well below this
// bound. The cap is a defense-in-depth guard against a misconfigured
// / malicious upstream returning a perpetually inflated paging.Total
// combined with a non-empty page on every request — the secondary
// next-empty guard would not catch that. Mirrors
// splunkGroupsMaxPages=2000 in groups.go and splunkAuditMaxPages=200
// in audit.go.
const splunkIdentitiesMaxPages = 2000

var ErrNotImplemented = fmt.Errorf("splunk: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	BaseURL string `json:"base_url"`
}

type Secrets struct {
	Token string `json:"token"`
}

type SplunkAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SplunkAccessConnector { return &SplunkAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("splunk: config is nil")
	}
	var cfg Config
	if v, ok := raw["base_url"].(string); ok {
		cfg.BaseURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("splunk: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["token"].(string); ok {
		s.Token = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("splunk: base_url is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("splunk: token is required")
	}
	return nil
}

func (c *SplunkAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SplunkAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
}

func (c *SplunkAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SplunkAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *SplunkAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("splunk: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("splunk: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, formatErrorBody(body))
	}
	return body, nil
}

// formatErrorBody returns a safe surface for an HTTP error-response
// body that will be embedded in an error message. Splunk's native
// error format is JSON (e.g. `{"messages":[{"type":"ERROR","text":...}]}`)
// and operators want to see it verbatim because it carries actionable
// upstream detail. HTML / XML / plaintext bodies, on the other hand,
// almost always come from an interposing reverse proxy or load
// balancer in front of Splunk (cloud LB error pages, maintenance
// notices, WAF blocks) — those bodies frequently embed trace IDs,
// cookie names, internal hostnames, and stack frames that should NOT
// land in operator dashboards or audit logs. For non-JSON bodies we
// emit only a kind+length hint so operators can still triage the
// upstream surface without leaking sensitive interposing-layer
// metadata.
//
// formatErrorBody is the single shared scrubbing helper used by every
// Splunk HTTP error-emitting path:
//
//   - do() — JSON-RPC style helpers (CountGroups / SyncGroups /
//     SyncGroupMembers / CountIdentities / SyncIdentities /
//     CheckSSOEnforcement).
//   - doRaw() — advanced.go: ProvisionAccess / RevokeAccess /
//     ListEntitlements need the status code branched explicitly
//     (transient retry semantics) so they can't go through do(),
//     but they call formatErrorBody at the error-message boundary.
//   - audit.go: FetchAccessAuditLogs handles its own response so it
//     can collapse 401/403/404 to ErrAuditNotAvailable, but the
//     residual non-2xx error message routes through formatErrorBody
//     too.
//
// Centralising the safe-surface treatment here means a future
// proxy-error-page format never has to be remembered at multiple
// call sites.
const splunkErrorBodyJSONCap = 4 << 10

func formatErrorBody(body []byte) string {
	if len(body) == 0 {
		return "(empty)"
	}
	kind := bodyKind(body)
	if kind == "json" {
		if len(body) > splunkErrorBodyJSONCap {
			return truncateAtRune(body, splunkErrorBodyJSONCap) + " …(truncated)"
		}
		return string(body)
	}
	return fmt.Sprintf("(kind=%s, len=%d)", kind, len(body))
}

// truncateAtRune returns the longest prefix of body of length <= max
// that ends on a valid UTF-8 rune boundary. Naive `string(body[:max])`
// can split a multi-byte rune (e.g. a UTF-8-encoded … = 0xE2 0x80 0xA6)
// and produce an invalid-UTF-8 surface in the error message. Splunk's
// native JSON error envelope is overwhelmingly ASCII so the boundary
// case is rare, but downstream consumers (Datadog log pipelines,
// OpenTelemetry exporters, JSON-serialised audit records) reject
// invalid UTF-8 strictly. Walking back at most utf8.UTFMax-1 = 3 bytes
// from the cap guarantees a clean boundary in O(1).
//
// When max >= len(body) the whole body is returned without indexing
// past the slice end — indexing body[len(body)] would panic. The current
// sole call site only invokes truncateAtRune when len(body) > max, but
// guarding inside the function future-proofs it for any caller that
// relaxes the precondition.
func truncateAtRune(body []byte, max int) string {
	if max >= len(body) {
		return string(body)
	}
	end := max
	for end > 0 && !utf8.RuneStart(body[end]) {
		end--
	}
	return string(body[:end])
}

// bodyKind returns a short hint about the upstream payload kind so
// operators reading an error message can route the incident without
// us echoing the body itself. The hints are best-effort — we look at
// the first non-whitespace byte and at a couple of well-known
// signatures. Anything starting with `<` defaults to "html" because
// reverse-proxy error pages overwhelmingly emit HTML fragments
// (`<div>…</div>`, `<p>maintenance</p>`); the explicit `<?xml`
// prefix is the only path that returns "xml".
//
// We only inspect the first bodyKindPrefixBytes of the body (after
// trimming leading whitespace). do() caps body reads at 1MB, so
// without this bound, the unparseable-body error path would allocate
// ~3MB just to check a 14-byte prefix every time a reverse proxy
// returns a verbose HTML page. Stack traces / error pages routinely
// exceed 100KB; the first 64 bytes are more than enough to identify
// HTML / XML / JSON / text.
const bodyKindPrefixBytes = 64

func bodyKind(body []byte) string {
	start := 0
	for start < len(body) {
		switch body[start] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			start++
			continue
		}
		break
	}
	if start >= len(body) {
		return "empty"
	}
	end := start + bodyKindPrefixBytes
	if end > len(body) {
		end = len(body)
	}
	prefix := strings.ToLower(string(body[start:end]))
	switch {
	case strings.HasPrefix(prefix, "<?xml"):
		return "xml"
	case strings.HasPrefix(prefix, "<"):
		// Default angle-bracketed payloads to "html" — HTML
		// fragments from proxies / load balancers /
		// maintenance pages are far more common than raw XML
		// in the wild, and operators reading kind=html will
		// correctly recognize a proxy-interposition surface.
		return "html"
	case strings.HasPrefix(prefix, "{"),
		strings.HasPrefix(prefix, "["):
		return "json"
	default:
		return "text"
	}
}

func (c *SplunkAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SplunkAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("%s/services/authentication/users?output_mode=json&count=1&offset=0", c.baseURL(cfg))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("splunk: connect probe: %w", err)
	}
	return nil
}

func (c *SplunkAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type splunkEntry struct {
	Name    string `json:"name"`
	Content struct {
		Email    string `json:"email"`
		RealName string `json:"realname"`
		Locked   bool   `json:"locked-out"`
	} `json:"content"`
}

type splunkListResponse struct {
	Entry  []splunkEntry `json:"entry"`
	Paging struct {
		Total   int `json:"total"`
		PerPage int `json:"perPage"`
		Offset  int `json:"offset"`
	} `json:"paging"`
}

func (c *SplunkAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SplunkAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
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
	base := c.baseURL(cfg)
	for pages := 0; pages < splunkIdentitiesMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/services/authentication/users?output_mode=json&count=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp splunkListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("splunk: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Entry))
		for _, e := range resp.Entry {
			display := e.Content.RealName
			if display == "" {
				display = e.Name
			}
			status := "active"
			if e.Content.Locked {
				status = "locked"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  e.Name,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       e.Content.Email,
				Status:      status,
			})
		}
		next := ""
		if offset+len(resp.Entry) < resp.Paging.Total && len(resp.Entry) > 0 {
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
	return fmt.Errorf("splunk: sync identities: pagination exceeded %d pages (server returned non-terminating paging.total)", splunkIdentitiesMaxPages)
}

// ProvisionAccess, RevokeAccess, ListEntitlements: see advanced.go.

func (c *SplunkAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return access.SSOMetadataFromConfig(configRaw, "saml"), nil
}

func (c *SplunkAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
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

var _ access.AccessConnector = (*SplunkAccessConnector)(nil)
