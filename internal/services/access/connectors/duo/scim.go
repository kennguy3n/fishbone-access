// Package duo — SCIM v2.0 outbound provisioning composition.
//
// Duo's Admin API at https://{api_hostname}/admin/v1 doubles as the
// SCIM provisioning surface. Unlike most SaaS, Duo authenticates
// every request with an HMAC-SHA1 signature (RFC 1123 date + method
// + host + path + canonical params), so the SCIMClient's static
// Authorization-header model can't carry the signature alone — the
// signature depends on the request itself.
//
// We solve this by wrapping the HTTP transport: each call builds a
// per-request signing transport that overwrites the Authorization
// + Date headers using the existing signDuoRequest helper. The
// SCIMClient still sets a placeholder Authorization header from
// scim_auth_header so its empty-header branching stays consistent;
// the transport unconditionally rewrites both headers.
package duo

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// duoSigningTransport wraps http.RoundTripper to insert the Duo
// HMAC-SHA1 Authorization + Date headers on each request.
type duoSigningTransport struct {
	host, ikey, skey string
	nowFn            func() time.Time
	inner            http.RoundTripper
}

func (t *duoSigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	now := time.Now().UTC
	if t.nowFn != nil {
		now = t.nowFn
	}
	date := now().Format(time.RFC1123Z)
	params := map[string]string{}
	if req.URL.RawQuery != "" {
		q := req.URL.Query()
		for k := range q {
			params[k] = q.Get(k)
		}
	}
	auth := signDuoRequest(req.Method, t.host, req.URL.Path, params, t.ikey, t.skey, date)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Date", date)
	inner := t.inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	return inner.RoundTrip(req)
}

// scimInnerTransport is the underlying RoundTripper used by the
// signing wrapper. Tests can install a custom transport here to
// capture signed roundtrips against an httptest.Server while
// observing the signed Authorization header.
var scimInnerTransport http.RoundTripper

// SetSCIMInnerTransportForTest installs an http.RoundTripper that
// the signing transport will delegate to. Returns the previous
// transport so the test can restore it via t.Cleanup.
func SetSCIMInnerTransportForTest(rt http.RoundTripper) http.RoundTripper {
	prev := scimInnerTransport
	scimInnerTransport = rt
	return prev
}

// newSCIMClient returns a fresh SCIMClient configured with the
// signing transport. A new client per call sidesteps the mutating
// WithHTTPClient on a shared package-level client.
func (c *DuoAccessConnector) newSCIMClient(secrets Secrets, host string) *access.SCIMClient {
	signing := &duoSigningTransport{
		host:  host,
		ikey:  secrets.IntegrationKey,
		skey:  secrets.SecretKey,
		nowFn: c.nowFn,
		inner: scimInnerTransport,
	}
	return access.NewSCIMClient().WithHTTPClient(&http.Client{Transport: signing})
}

// scimConfig adapts the Duo connector's config + secrets into the
// SCIMClient's config / secrets maps.
func (c *DuoAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, Config, Secrets, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, Config{}, Secrets{}, err
	}
	host := cfg.normalisedHost()
	scimBaseURL := "https://" + host + "/admin/v1"
	if c.urlOverride != "" {
		scimBaseURL = strings.TrimRight(c.urlOverride, "/") + "/admin/v1"
	}
	scimCfg := map[string]interface{}{
		"scim_base_url": scimBaseURL,
	}
	scimSecrets := map[string]interface{}{
		// SCIMClient skips the auth header when empty; supply a
		// placeholder so the SCIMClient still sets one and the
		// signing transport overwrites it.
		"scim_auth_header": "Basic placeholder",
	}
	return scimCfg, scimSecrets, cfg, secrets, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *DuoAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, cfg, secrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return c.newSCIMClient(secrets, cfg.normalisedHost()).PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *DuoAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, cfg, secrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return c.newSCIMClient(secrets, cfg.normalisedHost()).PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *DuoAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, cfg, secrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return c.newSCIMClient(secrets, cfg.normalisedHost()).DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

// Compile-time interface assertion.
var _ access.SCIMProvisioner = (*DuoAccessConnector)(nil)
