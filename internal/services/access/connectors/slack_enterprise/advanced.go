package slack_enterprise

import (
	"bytes"
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

// advanced-capability mapping for Slack Enterprise Grid (SCIM 2.0):
//
//   - ProvisionAccess  -> PATCH /scim/v2/Users/{id}
//                         op=add  path="groups" value=[{value: groupId}]
//   - RevokeAccess     -> PATCH /scim/v2/Users/{id}
//                         op=remove path=groups[value eq "{groupId}"]
//   - ListEntitlements -> GET   /scim/v2/Users/{id}
//                         → user.groups[*].value
//
// AccessGrant maps:
//   - grant.UserExternalID     -> SCIM user id (preferred) or userName/email
//   - grant.ResourceExternalID -> SCIM group id
//
// Bearer auth via slack_enterprise.newRequest.

func slackEnterpriseValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("slack_enterprise: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("slack_enterprise: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SlackEnterpriseAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *SlackEnterpriseAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("slack_enterprise: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

type scimUserWithGroups struct {
	scimUser
	Groups []scimGroupRef `json:"groups"`
}

type scimGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display"`
}

func (c *SlackEnterpriseAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := slackEnterpriseValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{
			"op":   "add",
			"path": "groups",
			"value": []map[string]string{{
				"value": strings.TrimSpace(grant.ResourceExternalID),
			}},
		}},
	}
	payload, _ := json.Marshal(patch)
	endpoint := fmt.Sprintf("%s/scim/v2/Users/%s", c.baseURL(),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPatch, endpoint, payload)
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
		return fmt.Errorf("slack_enterprise: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("slack_enterprise: provision status %d: %s", status, string(body))
	}
}

func (c *SlackEnterpriseAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := slackEnterpriseValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	gid := strings.TrimSpace(grant.ResourceExternalID)
	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{
			"op":   "remove",
			"path": fmt.Sprintf(`groups[value eq %q]`, gid),
		}},
	}
	payload, _ := json.Marshal(patch)
	endpoint := fmt.Sprintf("%s/scim/v2/Users/%s", c.baseURL(),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPatch, endpoint, payload)
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
		return fmt.Errorf("slack_enterprise: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("slack_enterprise: revoke status %d: %s", status, string(body))
	}
}

func (c *SlackEnterpriseAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("slack_enterprise: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/scim/v2/Users/%s", c.baseURL(), url.PathEscape(user))
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
		return nil, fmt.Errorf("slack_enterprise: list user status %d: %s", status, string(body))
	}
	var resp scimUserWithGroups
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("slack_enterprise: decode user: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Groups))
	for _, g := range resp.Groups {
		id := strings.TrimSpace(g.Value)
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(g.Display),
			Source:             "direct",
		})
	}
	return out, nil
}
