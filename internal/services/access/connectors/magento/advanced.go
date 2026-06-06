package magento

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

// advanced-capability mapping for Magento (Adobe Commerce):
//
//   - ProvisionAccess  -> POST   /rest/V1/customers
//   - RevokeAccess     -> DELETE /rest/V1/customers/{id}
//   - ListEntitlements -> GET    /rest/V1/customers/{id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Magento customer numeric id or email
//   - grant.ResourceExternalID -> Magento customer group id (e.g. "1" for General, "3" for Retailer)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func magentoValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("magento: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("magento: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *MagentoAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("magento: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *MagentoAccessConnector) customersURL(cfg Config) string {
	return c.baseURL(cfg) + "/rest/V1/customers"
}

func (c *MagentoAccessConnector) customerURL(cfg Config, userID string) string {
	return c.baseURL(cfg) + "/rest/V1/customers/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *MagentoAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *MagentoAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := magentoValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	groupID, parseErr := parseMagentoGroupID(grant.ResourceExternalID)
	if parseErr != nil {
		return parseErr
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"customer": map[string]interface{}{
			"email":   strings.TrimSpace(grant.UserExternalID),
			"groupId": groupID,
		},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.customersURL(cfg), payload)
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
		return fmt.Errorf("magento: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("magento: provision status %d: %s", status, string(body))
	}
}

func (c *MagentoAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := magentoValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.customerURL(cfg, grant.UserExternalID), nil)
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
		return fmt.Errorf("magento: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("magento: revoke status %d: %s", status, string(body))
	}
}

func (c *MagentoAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("magento: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.customerURL(cfg, user), nil)
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
		return nil, fmt.Errorf("magento: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		ID      json.Number `json:"id"`
		Email   string      `json:"email"`
		GroupID json.Number `json:"group_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("magento: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Email), user) &&
		strings.TrimSpace(resp.ID.String()) != user {
		return nil, nil
	}
	group := strings.TrimSpace(resp.GroupID.String())
	if group == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: group,
		Role:               group,
		Source:             "direct",
	}}, nil
}

func parseMagentoGroupID(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("magento: group id is required")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("magento: group id %q is not numeric", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}
