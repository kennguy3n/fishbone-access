package apollo

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

// advanced-capability mapping for apollo:
//
//   - ProvisionAccess  -> PUT    /v1/users/{user}/roles/{role}
//   - RevokeAccess     -> DELETE /v1/users/{user}/roles/{role}
//   - ListEntitlements -> GET    /v1/users/{user}/roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> apollo user identifier
//   - grant.ResourceExternalID -> apollo role identifier (round-trips in ListEntitlements)
//
// Idempotency is delegated to access.IsIdempotentProvisionStatus /
// access.IsIdempotentRevokeStatus per docs/architecture.md §2.

func apolloValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("apollo: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("apollo: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ApolloAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("apollo: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ApolloAccessConnector) grantURL(userExternalID, roleExternalID string) string {
	return fmt.Sprintf("%s/v1/users/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)),
		url.PathEscape(strings.TrimSpace(roleExternalID)))
}

func (c *ApolloAccessConnector) entitlementsURL(userExternalID string) string {
	return fmt.Sprintf("%s/v1/users/%s/roles",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)))
}

func (c *ApolloAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := apolloValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodPut, c.grantURL(grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("apollo: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("apollo: provision status %d: %s", status, string(body))
	}
}

func (c *ApolloAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := apolloValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, c.grantURL(grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("apollo: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("apollo: revoke status %d: %s", status, string(body))
	}
}

func (c *ApolloAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("apollo: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.entitlementsURL(user))
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
		return nil, fmt.Errorf("apollo: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Data []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		var bare []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		}
		if err2 := json.Unmarshal(body, &bare); err2 != nil {
			return nil, fmt.Errorf("apollo: decode entitlements: %w", err)
		}
		envelope.Data = bare
	}
	out := make([]access.Entitlement, 0, len(envelope.Data))
	for _, r := range envelope.Data {
		id := strings.TrimSpace(fmt.Sprintf("%v", r.ID))
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
