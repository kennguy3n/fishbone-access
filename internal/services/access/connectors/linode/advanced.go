package linode

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

// advanced-capability mapping for linode:
//
//   - ProvisionAccess  -> POST   /v4/account/users
//   - RevokeAccess     -> DELETE /v4/account/users/{username}
//   - ListEntitlements -> GET    /v4/account/users
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Linode account username (or email)
//   - grant.ResourceExternalID -> "restricted" or "unrestricted" role token
//   - grant.Scope["email"]     -> email used when creating the Linode user
//
// Bearer auth. Idempotent on (UserExternalID, ResourceExternalID).

func linodeValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("linode: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("linode: grant.ResourceExternalID is required")
	}
	return nil
}

// linodeResolveUserCreate derives the username and email for the
// POST /v4/account/users body. Linode requires a valid username (which
// disallows '@') and a separate, valid email address. SyncIdentities exports
// the Linode username as the identity ExternalID, so the email arrives
// out-of-band via grant.Scope["email"]; when the ExternalID is itself an
// email we use it as the email and derive the username from its local part.
// The username is never reused as the email — the real API rejects that and
// the connector could otherwise never provision successfully.
func linodeResolveUserCreate(grant access.AccessGrant) (username, email string, err error) {
	id := strings.TrimSpace(grant.UserExternalID)
	if v, ok := grant.Scope["email"].(string); ok {
		email = strings.TrimSpace(v)
	}
	if at := strings.IndexByte(id, '@'); at >= 0 {
		if email == "" {
			email = id
		}
		username = strings.TrimSpace(id[:at])
	} else {
		username = id
	}
	if username == "" {
		return "", "", errors.New("linode: could not derive a username for provisioning")
	}
	if email == "" {
		return "", "", fmt.Errorf("linode: an email is required to create user %q; supply grant.Scope[\"email\"] or an email-form UserExternalID", username)
	}
	return username, email, nil
}

func (c *LinodeAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("linode: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *LinodeAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *LinodeAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := linodeValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	username, email, err := linodeResolveUserCreate(grant)
	if err != nil {
		return err
	}
	restricted := strings.EqualFold(strings.TrimSpace(grant.ResourceExternalID), "restricted")
	payload, _ := json.Marshal(map[string]interface{}{
		"username":   username,
		"email":      email,
		"restricted": restricted,
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.baseURL()+"/v4/account/users", payload)
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
		return fmt.Errorf("linode: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("linode: provision status %d: %s", status, string(body))
	}
}

func (c *LinodeAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := linodeValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL() + "/v4/account/users/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("linode: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("linode: revoke status %d: %s", status, string(body))
	}
}

func (c *LinodeAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("linode: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	// GET /v4/account/users is paginated. SyncIdentities exports the username
	// as the ExternalID, so the target normally arrives keyed by username, but
	// we also tolerate matching by email; either way the user can sit on a
	// later page, so we must walk every page rather than inspecting only the
	// first one (which would wrongly report "no entitlements" for large
	// accounts). The loop is bounded by linodeMaxUserPages so a degenerate API
	// that always returns a full page cannot spin forever.
	base := c.baseURL()
	for page := 1; page <= linodeMaxUserPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := fmt.Sprintf("%s/v4/account/users?page=%d&page_size=%d", base, page, pageSize)
		req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, path, nil)
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
			return nil, fmt.Errorf("linode: list entitlements status %d: %s", status, string(body))
		}
		var envelope struct {
			Data []struct {
				Username   string `json:"username"`
				Email      string `json:"email"`
				Restricted bool   `json:"restricted"`
			} `json:"data"`
			Pages int `json:"pages"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("linode: decode entitlements: %w", err)
		}
		for _, u := range envelope.Data {
			if !strings.EqualFold(u.Username, user) && !strings.EqualFold(u.Email, user) {
				continue
			}
			role := "unrestricted"
			if u.Restricted {
				role = "restricted"
			}
			return []access.Entitlement{{
				ResourceExternalID: role,
				Role:               role,
				Source:             "direct",
			}}, nil
		}
		if envelope.Pages > 0 && page >= envelope.Pages {
			break
		}
		if len(envelope.Data) < pageSize {
			break
		}
	}
	return []access.Entitlement{}, nil
}
