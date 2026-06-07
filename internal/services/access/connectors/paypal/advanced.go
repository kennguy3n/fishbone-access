package paypal

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

// advanced-capability mapping for paypal (partner-merchant API):
//
//   - ProvisionAccess  -> POST   /v2/customer/partner-referrals
//                         body { tracking_id, operations:[{
//                            operation: API_INTEGRATION,
//                            api_integration_preference: {
//                              rest_api_integration: {
//                                features: [<feature>],
//                              },
//                            },
//                         }] }
//   - RevokeAccess     -> PATCH  /v1/customer/partners/{partner_id}/merchant-integrations/{tracking_id}
//                         body [{ op: "replace", path: "/payments_receivable", value: false }]
//   - ListEntitlements -> GET    /v1/customer/partners/{partner_id}/merchant-integrations
//                         filtered to the merchant whose tracking_id matches
//                         grant.UserExternalID; emits the granted features.
//
// AccessGrant maps:
//   - grant.UserExternalID     -> merchant tracking_id
//   - grant.ResourceExternalID -> partner-referral feature (e.g.
//                                 "PAYMENT", "REFUND", "PARTNER_FEE")
//
// Auth: short-lived OAuth2 bearer minted via accessToken(); idempotent
// on (UserExternalID, ResourceExternalID) per docs/architecture.md §2 — PayPal
// returns 409 / 422 for duplicate tracking ids and 404 once a merchant
// integration is fully deactivated.

func paypalValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("paypal: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("paypal: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PayPalAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.doHTTP(req)
	if err != nil {
		return 0, nil, fmt.Errorf("paypal: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *PayPalAccessConnector) newJSONRequest(ctx context.Context, token, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

func (c *PayPalAccessConnector) newPatchRequest(ctx context.Context, token, fullURL string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, fullURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json-patch+json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

func (c *PayPalAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := paypalValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"tracking_id": strings.TrimSpace(grant.UserExternalID),
		"operations": []map[string]interface{}{
			{
				"operation": "API_INTEGRATION",
				"api_integration_preference": map[string]interface{}{
					"rest_api_integration": map[string]interface{}{
						"integration_method": "PAYPAL",
						"integration_type":   "THIRD_PARTY",
						"third_party_details": map[string]interface{}{
							"features": []string{strings.TrimSpace(grant.ResourceExternalID)},
						},
					},
				},
			},
		},
	})
	endpoint := c.baseURL(cfg) + "/v2/customer/partner-referrals"
	req, err := c.newJSONRequest(ctx, token, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("paypal: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("paypal: provision status %d: %s", status, string(body))
	}
}

func (c *PayPalAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := paypalValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal([]map[string]interface{}{
		{"op": "replace", "path": "/payments_receivable", "value": false},
	})
	endpoint := fmt.Sprintf("%s/v1/customer/partners/%s/merchant-integrations/%s",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(cfg.PartnerID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)),
	)
	req, err := c.newPatchRequest(ctx, token, endpoint, payload)
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
		return fmt.Errorf("paypal: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("paypal: revoke status %d: %s", status, string(body))
	}
}

type paypalMerchantWithFeatures struct {
	MerchantID         string `json:"merchant_id"`
	TrackingID         string `json:"tracking_id"`
	PaymentsReceivable bool   `json:"payments_receivable"`
	Features           []struct {
		Name string `json:"name"`
	} `json:"granted_permissions"`
}

type paypalIntegrationsListResponse struct {
	MerchantIntegrations []paypalMerchantWithFeatures `json:"merchant_integrations"`
}

func (c *PayPalAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("paypal: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	token, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/v1/customer/partners/%s/merchant-integrations",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(cfg.PartnerID)),
	)
	req, err := c.newJSONRequest(ctx, token, http.MethodGet, endpoint, nil)
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
		return nil, fmt.Errorf("paypal: list entitlements status %d: %s", status, string(body))
	}
	var resp paypalIntegrationsListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("paypal: decode merchants: %w", err)
	}
	out := []access.Entitlement{}
	for _, m := range resp.MerchantIntegrations {
		if !strings.EqualFold(strings.TrimSpace(m.TrackingID), user) {
			continue
		}
		if !m.PaymentsReceivable {
			continue
		}
		for _, f := range m.Features {
			name := strings.TrimSpace(f.Name)
			if name == "" {
				continue
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: name,
				Role:               name,
				Source:             "direct",
			})
		}
	}
	return out, nil
}
