package circleci

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

// circleCIMaxRestrictionPages caps how many pages of context restrictions
// the connector will walk before giving up, so a malformed/looping
// next_page_token can never produce an unbounded request loop.
const circleCIMaxRestrictionPages = 1000

// advanced-capability mapping for CircleCI:
//
// CircleCI v2 does not expose org-member CRUD; the closest first-class
// permission resource is the "Context Restriction" that limits which
// projects can read a given context's secrets. The advanced
// capabilities therefore manage project ↔ context bindings:
//
//   - ProvisionAccess  -> POST   /api/v2/context/{context_id}/restrictions
//                                body {"project_id":"…"}
//   - RevokeAccess     -> DELETE /api/v2/context/{context_id}/restrictions/{restriction_id}
//   - ListEntitlements -> GET    /api/v2/context/{context_id}/restrictions
//
// AccessGrant maps:
//   - grant.UserExternalID     -> project_id (the "subject" being granted)
//   - grant.ResourceExternalID -> context_id (the resource)
//
// Idempotency:
//   - 400 with "already exists" body → idempotent provision per
//     access.IsIdempotentProvisionStatus.
//   - 404 on revoke → idempotent revoke per
//     access.IsIdempotentRevokeStatus.

func circleCIValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("circleci: grant.UserExternalID (project_id) is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("circleci: grant.ResourceExternalID (context_id) is required")
	}
	return nil
}

func (c *CircleCIAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Circle-Token", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *CircleCIAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("circleci: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ProvisionAccess binds the project to the context.
func (c *CircleCIAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := circleCIValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	contextID := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	payload, _ := json.Marshal(map[string]string{
		"project_id":        strings.TrimSpace(grant.UserExternalID),
		"restriction_type":  "project",
		"restriction_value": strings.TrimSpace(grant.UserExternalID),
	})
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost,
		c.baseURL()+"/api/v2/context/"+contextID+"/restrictions", payload)
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
		return fmt.Errorf("circleci: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("circleci: provision status %d: %s", status, string(body))
	}
}

// RevokeAccess removes the project's binding to the context.
func (c *CircleCIAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := circleCIValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	restrictionID, err := c.findCircleCIRestriction(ctx, secrets, grant)
	if err != nil {
		return err
	}
	if restrictionID == "" {
		return nil
	}
	contextID := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete,
		c.baseURL()+"/api/v2/context/"+contextID+"/restrictions/"+url.PathEscape(restrictionID), nil)
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
		return fmt.Errorf("circleci: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("circleci: revoke status %d: %s", status, string(body))
	}
}

// ListEntitlements returns the contexts the project is currently
// permitted to read. userExternalID is the project_id.
func (c *CircleCIAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	project := strings.TrimSpace(userExternalID)
	if project == "" {
		return nil, errors.New("circleci: user external id (project_id) is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	base := c.baseURL() + "/api/v2/context/restrictions?project_id=" + url.QueryEscape(project)
	var out []access.Entitlement
	pageToken := ""
	for page := 0; page < circleCIMaxRestrictionPages; page++ {
		fullURL := base
		if pageToken != "" {
			fullURL += "&page-token=" + url.QueryEscape(pageToken)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return nil, err
		}
		status, body, err := c.doRaw(req)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			return out, nil
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("circleci: list entitlements status %d: %s", status, string(body))
		}
		var resp circleCIRestrictionsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("circleci: decode restrictions: %w", err)
		}
		for i := range resp.Items {
			ctxID := strings.TrimSpace(resp.Items[i].ContextID)
			val := strings.TrimSpace(resp.Items[i].RestrictionValue)
			if val != project && val != "" {
				continue
			}
			if ctxID == "" {
				continue
			}
			out = append(out, access.Entitlement{
				ResourceExternalID: ctxID,
				Role:               "project",
				Source:             "direct",
			})
		}
		pageToken = strings.TrimSpace(resp.NextPageToken)
		if pageToken == "" {
			break
		}
	}
	return out, nil
}

func (c *CircleCIAccessConnector) findCircleCIRestriction(ctx context.Context, secrets Secrets, grant access.AccessGrant) (string, error) {
	contextID := url.PathEscape(strings.TrimSpace(grant.ResourceExternalID))
	base := c.baseURL() + "/api/v2/context/" + contextID + "/restrictions"
	want := strings.TrimSpace(grant.UserExternalID)
	pageToken := ""
	for page := 0; page < circleCIMaxRestrictionPages; page++ {
		fullURL := base
		if pageToken != "" {
			fullURL += "?page-token=" + url.QueryEscape(pageToken)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return "", err
		}
		status, body, err := c.doRaw(req)
		if err != nil {
			return "", err
		}
		if status == http.StatusNotFound {
			return "", nil
		}
		if status < 200 || status >= 300 {
			return "", fmt.Errorf("circleci: list restrictions status %d: %s", status, string(body))
		}
		var resp circleCIRestrictionsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("circleci: decode restrictions: %w", err)
		}
		for i := range resp.Items {
			if strings.TrimSpace(resp.Items[i].RestrictionValue) == want ||
				strings.TrimSpace(resp.Items[i].ProjectID) == want {
				return strings.TrimSpace(resp.Items[i].ID), nil
			}
		}
		pageToken = strings.TrimSpace(resp.NextPageToken)
		if pageToken == "" {
			break
		}
	}
	return "", nil
}

type circleCIRestrictionsResponse struct {
	Items []struct {
		ID               string `json:"id"`
		ContextID        string `json:"context_id"`
		ProjectID        string `json:"project_id"`
		RestrictionType  string `json:"restriction_type"`
		RestrictionValue string `json:"restriction_value"`
	} `json:"items"`
	NextPageToken string `json:"next_page_token"`
}
