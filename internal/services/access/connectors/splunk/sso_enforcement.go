// Package splunk — SSOEnforcementChecker via authentication config.
//
// Splunk Cloud / Enterprise expose the active authentication method
// via:
//
//	GET /services/properties/authentication/authentication/authType?output_mode=json
//
// The response is a single-entry envelope whose `entry[0].content`
// equals the active authType — one of:
//
//	"Splunk"   -> built-in Splunk auth (password fallback enabled)
//	"LDAP"     -> external LDAP directory
//	"SAML"     -> SAML SSO (SSO enforced; local Splunk password
//	               fallback disabled unless explicitly re-enabled
//	               per-user via a Splunk admin)
//	"Scripted" -> external scripted auth handler
//
// The check therefore returns (true, ...) only when authType == "SAML"
// (case-insensitive). Any other value — including the bypass-able
// "Splunk" — is reported as (false, ...) with a clear detail string.
// Transport / auth errors surface to the caller so the health
// endpoint can route them to "unknown" rather than "not_enforced".
package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type splunkAuthTypeResponse struct {
	Entry []struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"entry"`
}

// splunkAuthTypeShape matches the known Splunk authType identifier
// surface — a short, ASCII-only token that begins with a letter and
// contains only letters, digits, underscore, hyphen, or dot. The
// canonical values ("Splunk", "LDAP", "SAML", "Scripted") all conform;
// the bound deliberately admits any future identifier Splunk might
// add (e.g. "OIDC", "ProxySSO") without re-touching this file. The
// length cap of 32 is generous compared to the longest documented
// value ("Scripted") but strict enough to reject HTML error pages,
// plaintext stack traces, and anything else a reverse proxy or load
// balancer in front of Splunk might surface during an outage.
var splunkAuthTypeShape = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.\-]{0,31}$`)

func (c *SplunkAccessConnector) CheckSSOEnforcement(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
) (enforced bool, details string, err error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	endpoint := c.baseURL(cfg) + "/services/properties/authentication/authentication/authType?output_mode=json"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return false, "", err
	}
	body, err := c.do(req)
	if err != nil {
		return false, "", fmt.Errorf("splunk: sso check: %w", err)
	}
	// Splunk's /services/properties/.../authType endpoint can return
	// either a JSON envelope (the common case with `output_mode=json`)
	// or — on older / mis-configured installations — a bare string.
	// Try the envelope first; only if the body is not parseable as
	// JSON at all do we treat the raw body as the authType value.
	// This avoids leaking raw JSON like `{"entry":[]}` into the
	// detail string when the envelope is well-formed but empty.
	//
	// Three "no authType" outcomes are possible, each mapped to the
	// SSOEnforcementChecker contract surface — see optional_interfaces.go
	// (nil error + enforced=false = "not_enforced" / regression signal;
	// non-nil error = "unknown" / check could not complete):
	//
	//   - The envelope parsed but entry[]/content was empty: this is
	//     a legitimate Splunk response that says "no authType is
	//     configured" — the documented Splunk default is local auth,
	//     so we return (false, "authType field empty…", nil). That
	//     maps to "not_enforced", which is correct.
	//
	//   - The body did not parse as JSON but matches a known authType
	//     identifier shape (short ASCII token): treat the raw body as
	//     authType. This is the old-Splunk bare-string response path.
	//
	//   - The body did not parse as JSON AND does not match the
	//     known authType shape (HTML 502 page from a reverse proxy,
	//     plaintext maintenance notice from a load balancer, any
	//     other non-Splunk surface): we did NOT successfully complete
	//     the check, so the contract requires a non-nil error so the
	//     health endpoint maps the result to "unknown" rather than
	//     misclassifying a transient upstream-proxy outage as a
	//     confirmed SSO regression (which would fire false-positive
	//     alerts on the daily orphan-reconciler scan). The error
	//     surface only carries a length + content-kind hint, never
	//     the body itself, because the body can be megabytes long
	//     and may contain sensitive request/response metadata the
	//     interposing layer chose to render (trace IDs, cookie names,
	//     error backtraces) — neither of which belongs in operator
	//     dashboards or audit logs.
	var authType string
	var env splunkAuthTypeResponse
	if jsonErr := json.Unmarshal(body, &env); jsonErr == nil {
		if len(env.Entry) > 0 {
			authType = strings.TrimSpace(env.Entry[0].Content)
		}
	} else {
		raw := strings.TrimSpace(string(body))
		if splunkAuthTypeShape.MatchString(raw) {
			authType = raw
		} else {
			return false, "", fmt.Errorf(
				"splunk: sso check: upstream returned unparseable authType response (kind=%s, len=%d)",
				bodyKind(body),
				len(body),
			)
		}
	}
	if strings.EqualFold(authType, "SAML") {
		return true, "authType=SAML; SAML SSO enforced", nil
	}
	if authType == "" {
		return false, "authType field empty; assuming local Splunk auth", nil
	}
	return false, fmt.Sprintf("authType=%s; SAML SSO not enforced", authType), nil
}

var _ access.SSOEnforcementChecker = (*SplunkAccessConnector)(nil)
