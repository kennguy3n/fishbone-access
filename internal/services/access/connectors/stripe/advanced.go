package stripe

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

// advanced-capability mapping for stripe (Connect):
//
//   - ProvisionAccess  -> POST   /v1/accounts/{account}/capabilities/{capability}
//                         with form-encoded requested=true.
//   - RevokeAccess     -> POST   /v1/accounts/{account}/capabilities/{capability}
//                         with form-encoded requested=false (Stripe does
//                         not expose a true DELETE for capabilities).
//   - ListEntitlements -> GET    /v1/accounts/{account}/capabilities
//                         and return the capabilities whose status is
//                         "active" or "pending".
//
// AccessGrant maps:
//   - grant.UserExternalID     -> connected account id (acct_...)
//   - grant.ResourceExternalID -> capability identifier (e.g.
//                                 "card_payments", "transfers")
//
// Bearer auth reuses the existing connector.newRequest helper.
// Idempotent on (UserExternalID, ResourceExternalID): Stripe returns
// 200 even when the capability is already requested.

func stripeValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("stripe: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("stripe: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *StripeAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("stripe: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *StripeAccessConnector) newFormRequest(ctx context.Context, secrets Secrets, method, fullURL string, form url.Values) (*http.Request, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.SecretKey))
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return req, nil
}

func stripeCapabilityURL(base, account, capability string) string {
	return base + "/v1/accounts/" + url.PathEscape(strings.TrimSpace(account)) +
		"/capabilities/" + url.PathEscape(strings.TrimSpace(capability))
}

func (c *StripeAccessConnector) updateCapability(ctx context.Context, secrets Secrets, grant access.AccessGrant, requested bool) (int, []byte, error) {
	form := url.Values{}
	if requested {
		form.Set("requested", "true")
	} else {
		form.Set("requested", "false")
	}
	endpoint := stripeCapabilityURL(c.baseURL(), grant.UserExternalID, grant.ResourceExternalID)
	req, err := c.newFormRequest(ctx, secrets, http.MethodPost, endpoint, form)
	if err != nil {
		return 0, nil, err
	}
	return c.doRaw(req)
}

func (c *StripeAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := stripeValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	status, body, err := c.updateCapability(ctx, secrets, grant, true)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("stripe: provision transient status %d: %s", status, httputil.SafeErrorBody(body))
	default:
		return fmt.Errorf("stripe: provision status %d: %s", status, httputil.SafeErrorBody(body))
	}
}

func (c *StripeAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := stripeValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	status, body, err := c.updateCapability(ctx, secrets, grant, false)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("stripe: revoke transient status %d: %s", status, httputil.SafeErrorBody(body))
	default:
		return fmt.Errorf("stripe: revoke status %d: %s", status, httputil.SafeErrorBody(body))
	}
}

func (c *StripeAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("stripe: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL() + "/v1/accounts/" + url.PathEscape(user) + "/capabilities"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("stripe: list entitlements status %d: %s", status, httputil.SafeErrorBody(body))
	}
	var envelope struct {
		Data []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("stripe: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Data))
	for _, d := range envelope.Data {
		status := strings.ToLower(strings.TrimSpace(d.Status))
		if status != "active" && status != "pending" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(d.ID),
			Role:               status,
			Source:             "direct",
		})
	}
	return out, nil
}
