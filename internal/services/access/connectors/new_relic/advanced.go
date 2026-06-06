package new_relic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for New Relic NerdGraph user
// management:
//
//   - ProvisionAccess  -> userManagementAddUsersToGroups
//   - RevokeAccess     -> userManagementRemoveUsersFromGroups
//   - ListEntitlements -> userManagement.authenticationDomains.users.groups
//
// AccessGrant maps:
//   - grant.UserExternalID     -> NerdGraph user `id`
//   - grant.ResourceExternalID -> NerdGraph group `id`
//
// NerdGraph mutations return the resulting group set rather than
// failing on duplicate membership, so ProvisionAccess is naturally
// idempotent. RevokeAccess treats GraphQL errors mentioning "not a
// member" / "not found" as idempotent success per docs/architecture.md §2.

func newRelicValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("new_relic: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("new_relic: grant.ResourceExternalID (group id) is required")
	}
	return nil
}

const newRelicAddUserToGroupMutation = `mutation($groupIds: [ID!]!, $userIds: [ID!]!) {
  userManagementAddUsersToGroups(addUsersToGroupsOptions: {groupIds: $groupIds, userIds: $userIds}) {
    groups { id displayName }
  }
}`

const newRelicRemoveUserFromGroupMutation = `mutation($groupIds: [ID!]!, $userIds: [ID!]!) {
  userManagementRemoveUsersFromGroups(removeUsersFromGroupsOptions: {groupIds: $groupIds, userIds: $userIds}) {
    groups { id displayName }
  }
}`

const newRelicListUserGroupsQuery = `query($userId: ID!) {
  actor {
    organization {
      userManagement {
        authenticationDomains {
          authenticationDomains {
            users(filter: {id: $userId}) {
              users {
                id
                groups { groups { id displayName } }
              }
            }
          }
        }
      }
    }
  }
}`

// ProvisionAccess adds the user to the group.
func (c *NewRelicAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := newRelicValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	vars := map[string]interface{}{
		"groupIds": []string{strings.TrimSpace(grant.ResourceExternalID)},
		"userIds":  []string{strings.TrimSpace(grant.UserExternalID)},
	}
	status, body, err := c.runGraphQL(ctx, cfg, secrets, newRelicAddUserToGroupMutation, vars)
	if err != nil {
		return err
	}
	if status >= 200 && status < 300 {
		if !newRelicGraphQLErrorBody(body) {
			return nil
		}
		if newRelicIsIdempotentBody(body) {
			return nil
		}
		return fmt.Errorf("new_relic: provision graphql error: %s", string(body))
	}
	if access.IsIdempotentProvisionStatus(status, body) {
		return nil
	}
	if access.IsTransientStatus(status) {
		return fmt.Errorf("new_relic: provision transient status %d: %s", status, string(body))
	}
	return fmt.Errorf("new_relic: provision status %d: %s", status, string(body))
}

// RevokeAccess removes the user from the group.
func (c *NewRelicAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := newRelicValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	vars := map[string]interface{}{
		"groupIds": []string{strings.TrimSpace(grant.ResourceExternalID)},
		"userIds":  []string{strings.TrimSpace(grant.UserExternalID)},
	}
	status, body, err := c.runGraphQL(ctx, cfg, secrets, newRelicRemoveUserFromGroupMutation, vars)
	if err != nil {
		return err
	}
	if status >= 200 && status < 300 {
		if !newRelicGraphQLErrorBody(body) {
			return nil
		}
		if newRelicIsIdempotentBody(body) {
			return nil
		}
		return fmt.Errorf("new_relic: revoke graphql error: %s", string(body))
	}
	if access.IsIdempotentRevokeStatus(status, body) {
		return nil
	}
	if access.IsTransientStatus(status) {
		return fmt.Errorf("new_relic: revoke transient status %d: %s", status, string(body))
	}
	return fmt.Errorf("new_relic: revoke status %d: %s", status, string(body))
}

// ListEntitlements returns the groups the user currently belongs to.
func (c *NewRelicAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("new_relic: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	vars := map[string]interface{}{"userId": user}
	status, body, err := c.runGraphQL(ctx, cfg, secrets, newRelicListUserGroupsQuery, vars)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("new_relic: list entitlements status %d: %s", status, string(body))
	}
	var parsed newRelicUserGroupsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("new_relic: decode user groups: %w", err)
	}
	if len(parsed.Errors) > 0 {
		return nil, fmt.Errorf("new_relic: list entitlements graphql error: %s", parsed.Errors[0].Message)
	}
	var out []access.Entitlement
	domains := parsed.Data.Actor.Organization.UserManagement.AuthenticationDomains.AuthenticationDomains
	for i := range domains {
		for u := range domains[i].Users.Users {
			if strings.TrimSpace(domains[i].Users.Users[u].ID) != user {
				continue
			}
			for _, g := range domains[i].Users.Users[u].Groups.Groups {
				id := strings.TrimSpace(g.ID)
				if id == "" {
					continue
				}
				out = append(out, access.Entitlement{
					ResourceExternalID: id,
					Role:               strings.TrimSpace(g.DisplayName),
					Source:             "direct",
				})
			}
		}
	}
	return out, nil
}

func (c *NewRelicAccessConnector) runGraphQL(ctx context.Context, cfg Config, secrets Secrets, query string, vars map[string]interface{}) (int, []byte, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"query":     query,
		"variables": vars,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL(cfg)+"/graphql", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("API-Key", strings.TrimSpace(secrets.APIKey))
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("new_relic: graphql: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func newRelicGraphQLErrorBody(body []byte) bool {
	var probe struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return len(probe.Errors) > 0
}

func newRelicIsIdempotentBody(body []byte) bool {
	if !newRelicGraphQLErrorBody(body) {
		return false
	}
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "already") ||
		strings.Contains(lower, "not a member") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "duplicate") ||
		strings.Contains(lower, "no change")
}

type newRelicUserGroupsResponse struct {
	Data struct {
		Actor struct {
			Organization struct {
				UserManagement struct {
					AuthenticationDomains struct {
						AuthenticationDomains []struct {
							Users struct {
								Users []struct {
									ID     string `json:"id"`
									Groups struct {
										Groups []struct {
											ID          string `json:"id"`
											DisplayName string `json:"displayName"`
										} `json:"groups"`
									} `json:"groups"`
								} `json:"users"`
							} `json:"users"`
						} `json:"authenticationDomains"`
					} `json:"authenticationDomains"`
				} `json:"userManagement"`
			} `json:"organization"`
		} `json:"actor"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}
