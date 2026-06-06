package mezmo

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

// advanced-capability mapping for Mezmo:
//
//   - ProvisionAccess  -> POST   /v1/config/members          (email + role)
//   - RevokeAccess     -> DELETE /v1/config/members/{member} (by email or id)
//   - ListEntitlements -> GET    /v1/config/members          (filter by user)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> {email}  (Mezmo addresses members by email)
//   - grant.ResourceExternalID -> {role}   (e.g. "admin", "member", "owner")
//   - grant.Role               -> overrides ResourceExternalID if non-empty
//
// All mutations are idempotent: adding an existing member with the
// same role is treated as success, and deleting a non-existent member
// is treated as success per docs/architecture.md §2.

func mezmoValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("mezmo: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" && strings.TrimSpace(g.Role) == "" {
		return errors.New("mezmo: grant.ResourceExternalID (role) is required")
	}
	return nil
}

func mezmoRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	return strings.TrimSpace(g.ResourceExternalID)
}

func (c *MezmoAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "servicekey "+strings.TrimSpace(secrets.ServiceKey))
	return req, nil
}

func (c *MezmoAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("mezmo: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess invites the user identified by grant.UserExternalID
// (an email address) with the role from grant.Role / ResourceExternalID.
func (c *MezmoAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := mezmoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  mezmoRole(grant),
	})
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		c.baseURL()+"/v1/config/members", payload)
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
		return fmt.Errorf("mezmo: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("mezmo: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the member. 404 is treated as idempotent
// success per docs/architecture.md §2.
func (c *MezmoAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := mezmoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	member := url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete,
		c.baseURL()+"/v1/config/members/"+member, nil)
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
		return fmt.Errorf("mezmo: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("mezmo: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the role currently assigned to the user.
// Mezmo does not address members by stable id externally; the user
// external id is matched against both email and member id.
func (c *MezmoAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("mezmo: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/v1/config/members")
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
		return nil, fmt.Errorf("mezmo: list entitlements status %d: %s", status, string(body))
	}
	var members []mezmoMember
	if err := json.Unmarshal(body, &members); err != nil {
		var wrapper struct {
			Members []mezmoMember `json:"members"`
		}
		if err2 := json.Unmarshal(body, &wrapper); err2 != nil {
			return nil, fmt.Errorf("mezmo: decode members: %w", err)
		}
		members = wrapper.Members
	}
	lower := strings.ToLower(user)
	out := make([]access.Entitlement, 0, 1)
	for _, m := range members {
		if strings.EqualFold(m.Email, user) || m.ID == user {
			role := strings.TrimSpace(m.Role)
			if role == "" {
				role = "member"
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: role,
				Role:               role,
				Source:             "direct",
			})
			break
		}
		_ = lower
	}
	return out, nil
}
