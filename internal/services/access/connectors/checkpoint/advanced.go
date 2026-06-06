package checkpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for Check Point /web_api administrators:
//
//   - ProvisionAccess  -> POST /web_api/add-administrator     {name, permissions-profile}
//   - RevokeAccess     -> POST /web_api/delete-administrator  {name}
//   - ListEntitlements -> POST /web_api/show-administrator    {name}
//
// All /web_api/* verbs are POSTs carrying a JSON body and authenticate via
// the X-chkp-sid session header (shared helper `newPostJSON` in
// connector.go). Idempotent on (UserExternalID, ResourceExternalID) per
// docs/architecture.md §2.

func checkpointValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("checkpoint: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("checkpoint: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *CheckPointAccessConnector) verbURL(verb string) string {
	return c.baseURL() + "/web_api/" + verb
}

func (c *CheckPointAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("checkpoint: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *CheckPointAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := checkpointValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"name":                strings.TrimSpace(grant.UserExternalID),
		"permissions-profile": strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newPostJSON(ctx, secrets, c.verbURL("add-administrator"), payload)
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
		return fmt.Errorf("checkpoint: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("checkpoint: provision status %d: %s", status, string(body))
	}
}

func (c *CheckPointAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := checkpointValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"name": strings.TrimSpace(grant.UserExternalID),
	})
	req, err := c.newPostJSON(ctx, secrets, c.verbURL("delete-administrator"), payload)
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
		return fmt.Errorf("checkpoint: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("checkpoint: revoke status %d: %s", status, string(body))
	}
}

func (c *CheckPointAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("checkpoint: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]interface{}{"name": user})
	req, err := c.newPostJSON(ctx, secrets, c.verbURL("show-administrator"), payload)
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
		return nil, fmt.Errorf("checkpoint: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Name               string `json:"name"`
		PermissionsProfile string `json:"permissions-profile"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("checkpoint: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Name), user) {
		return nil, nil
	}
	profile := strings.TrimSpace(resp.PermissionsProfile)
	if profile == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: profile,
		Role:               profile,
		Source:             "direct",
	}}, nil
}
