package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for tailscale:
//
//   - ProvisionAccess  -> POST   /api/v2/device/{deviceID}/authorized
//   - RevokeAccess     -> POST   /api/v2/device/{deviceID}/authorized
//     (with {"authorized": false} body)
//   - ListEntitlements -> GET    /api/v2/tailnet/{tailnet}/devices
//     filtered by user (ResourceExternalID identifies the device).
//
// Tailscale's user-role surface is device-centric: provisioning a
// "grant" maps to authorising the device against the tailnet so the
// user (UserExternalID) can route through it. Revoke clears the
// authorized flag. Both calls are idempotent on
// (grant.UserExternalID, grant.ResourceExternalID) per docs/architecture.md §2
// — Tailscale returns 200 OK for repeated PUTs and 404 when the
// device is unknown.

func tailscaleValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("tailscale: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("tailscale: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *TailscaleAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("tailscale: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *TailscaleAccessConnector) deviceAuthorizedURL(deviceID string) string {
	return c.baseURL() + "/api/v2/device/" + url.PathEscape(strings.TrimSpace(deviceID)) + "/authorized"
}

func (c *TailscaleAccessConnector) devicesURL(tailnet string) string {
	return c.baseURL() + "/api/v2/tailnet/" + url.PathEscape(strings.TrimSpace(tailnet)) + "/devices"
}

func (c *TailscaleAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(strings.TrimSpace(secrets.APIKey), "")
	return req, nil
}

func (c *TailscaleAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := tailscaleValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost,
		c.deviceAuthorizedURL(grant.ResourceExternalID),
		[]byte(`{"authorized":true}`))
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("tailscale: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("tailscale: provision status %d: %s", status, string(body))
	}
}

func (c *TailscaleAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := tailscaleValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost,
		c.deviceAuthorizedURL(grant.ResourceExternalID),
		[]byte(`{"authorized":false}`))
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("tailscale: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("tailscale: revoke status %d: %s", status, string(body))
	}
}

func (c *TailscaleAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("tailscale: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.devicesURL(cfg.Tailnet), nil)
	if err != nil {
		return nil, err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("tailscale: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Devices []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			User       string `json:"user"`
			Authorized bool   `json:"authorized"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("tailscale: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Devices))
	for _, d := range envelope.Devices {
		if !d.Authorized {
			continue
		}
		if strings.TrimSpace(d.User) != user && strings.TrimSpace(d.Name) != user {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(d.ID),
			Role:               "authorized_device",
			Source:             "direct",
		})
	}
	return out, nil
}
