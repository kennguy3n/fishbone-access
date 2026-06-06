package wave

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

// advanced-capability mapping for Wave (GraphQL):
//
//   - ProvisionAccess  -> mutation userRoleAssign(userId, roleId)
//   - RevokeAccess     -> mutation userRoleRemove(userId, roleId)
//   - ListEntitlements -> query   userRoles(userId)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Wave user GUID
//   - grant.ResourceExternalID -> Wave role id
//
// Bearer auth via POST /graphql/public.

func waveValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("wave: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("wave: grant.ResourceExternalID is required")
	}
	return nil
}

type waveMutationResp struct {
	Data struct {
		UserRoleAssign struct {
			DidSucceed bool `json:"didSucceed"`
			Errors     []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		} `json:"userRoleAssign"`
		UserRoleRemove struct {
			DidSucceed bool `json:"didSucceed"`
			Errors     []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		} `json:"userRoleRemove"`
		UserRoles []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"userRoles"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *WaveAccessConnector) gqlPost(ctx context.Context, token, query string, vars map[string]interface{}) (int, *waveMutationResp, error) {
	payload, _ := json.Marshal(map[string]interface{}{"query": query, "variables": vars})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/graphql/public", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("wave: graphql: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, nil, fmt.Errorf("wave: graphql status %d: %s", resp.StatusCode, string(body))
	}
	var parsed waveMutationResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("wave: decode graphql: %w", err)
	}
	return resp.StatusCode, &parsed, nil
}

const waveAssignMutation = `mutation($userId: ID!, $roleId: ID!) { userRoleAssign(input: {userId: $userId, roleId: $roleId}) { didSucceed errors { code message } } }`
const waveRevokeMutation = `mutation($userId: ID!, $roleId: ID!) { userRoleRemove(input: {userId: $userId, roleId: $roleId}) { didSucceed errors { code message } } }`
const waveListQuery = `query($userId: ID!) { userRoles(userId: $userId) { id name } }`

func (c *WaveAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := waveValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_, parsed, err := c.gqlPost(ctx, secrets.Token, waveAssignMutation, map[string]interface{}{
		"userId": grant.UserExternalID,
		"roleId": grant.ResourceExternalID,
	})
	if err != nil {
		return err
	}
	if parsed.Data.UserRoleAssign.DidSucceed {
		return nil
	}
	for _, e := range parsed.Data.UserRoleAssign.Errors {
		if strings.EqualFold(e.Code, "ALREADY_ASSIGNED") || strings.EqualFold(e.Code, "CONFLICT") {
			return nil
		}
	}
	if len(parsed.Errors) > 0 {
		return fmt.Errorf("wave: provision graphql: %s", parsed.Errors[0].Message)
	}
	if len(parsed.Data.UserRoleAssign.Errors) > 0 {
		return fmt.Errorf("wave: provision graphql: %s", parsed.Data.UserRoleAssign.Errors[0].Message)
	}
	return errors.New("wave: provision failed without explicit error")
}

func (c *WaveAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := waveValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_, parsed, err := c.gqlPost(ctx, secrets.Token, waveRevokeMutation, map[string]interface{}{
		"userId": grant.UserExternalID,
		"roleId": grant.ResourceExternalID,
	})
	if err != nil {
		return err
	}
	if parsed.Data.UserRoleRemove.DidSucceed {
		return nil
	}
	for _, e := range parsed.Data.UserRoleRemove.Errors {
		if strings.EqualFold(e.Code, "NOT_FOUND") || strings.EqualFold(e.Code, "ALREADY_REMOVED") {
			return nil
		}
	}
	if len(parsed.Errors) > 0 {
		return fmt.Errorf("wave: revoke graphql: %s", parsed.Errors[0].Message)
	}
	if len(parsed.Data.UserRoleRemove.Errors) > 0 {
		return fmt.Errorf("wave: revoke graphql: %s", parsed.Data.UserRoleRemove.Errors[0].Message)
	}
	return errors.New("wave: revoke failed without explicit error")
}

func (c *WaveAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("wave: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	_, parsed, err := c.gqlPost(ctx, secrets.Token, waveListQuery, map[string]interface{}{"userId": user})
	if err != nil {
		return nil, err
	}
	if len(parsed.Errors) > 0 {
		return nil, fmt.Errorf("wave: list roles graphql: %s", parsed.Errors[0].Message)
	}
	out := make([]access.Entitlement, 0, len(parsed.Data.UserRoles))
	for _, r := range parsed.Data.UserRoles {
		id := strings.TrimSpace(r.ID)
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(r.Name),
			Source:             "direct",
		})
	}
	return out, nil
}
