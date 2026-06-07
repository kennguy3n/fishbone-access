package terraform

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

// advanced-capability mapping for Terraform Cloud:
//
//   - ProvisionAccess  -> POST   /api/v2/teams/{team_id}/relationships/users
//   - RevokeAccess     -> DELETE /api/v2/teams/{team_id}/relationships/users
//   - ListEntitlements -> GET    /api/v2/users/{user_id}/team-memberships
//
// The relationship endpoint uses the JSON:API "relationships" payload
// shape: `{ "data": [ { "type": "users", "id": "{user_id}" } ] }`.
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {user_id}
//   - grant.ResourceExternalID -> {team_id}
//   - grant.Role               -> team display name (round-tripped on
//     the Entitlement when present)

func terraformValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("terraform: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("terraform: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *TerraformAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *TerraformAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("terraform: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *TerraformAccessConnector) teamMembersURL(teamID string) string {
	return fmt.Sprintf("%s/api/v2/teams/%s/relationships/users",
		c.baseURL(), url.PathEscape(strings.TrimSpace(teamID)))
}

func tfRelationshipPayload(userID string) []byte {
	payload, _ := json.Marshal(map[string]interface{}{
		"data": []map[string]interface{}{
			{"type": "users", "id": strings.TrimSpace(userID)},
		},
	})
	return payload
}

// ProvisionAccess adds the user to the team. Idempotent on the
// (user, team) pair per docs/architecture.md §2.
func (c *TerraformAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := terraformValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		c.teamMembersURL(grant.ResourceExternalID), tfRelationshipPayload(grant.UserExternalID))
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
		return fmt.Errorf("terraform: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("terraform: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the user from the team. 404 / "not found"
// responses count as idempotent success.
func (c *TerraformAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := terraformValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete,
		c.teamMembersURL(grant.ResourceExternalID), tfRelationshipPayload(grant.UserExternalID))
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
		return fmt.Errorf("terraform: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("terraform: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the teams the user is currently a member of.
func (c *TerraformAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("terraform: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	fullURL := fmt.Sprintf("%s/api/v2/users/%s/team-memberships",
		c.baseURL(), url.PathEscape(user))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
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
		return nil, fmt.Errorf("terraform: list memberships status %d: %s", status, string(body))
	}
	var resp tfMembershipsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("terraform: decode memberships: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.Data))
	for _, m := range resp.Data {
		teamID := strings.TrimSpace(m.Relationships.Team.Data.ID)
		if teamID == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: teamID,
			Role:               m.Attributes.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

type tfMembershipsResponse struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes struct {
			Name string `json:"name"`
		} `json:"attributes"`
		Relationships struct {
			Team struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"team"`
		} `json:"relationships"`
	} `json:"data"`
}
