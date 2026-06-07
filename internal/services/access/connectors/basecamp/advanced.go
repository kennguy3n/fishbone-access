package basecamp

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

// advanced-capability mapping for Basecamp 3:
//
//   - ProvisionAccess  -> POST   /projects/{project_id}/people/new.json
//                         body {email_address, name?}
//   - RevokeAccess     -> DELETE /projects/{project_id}/people/{person_id}.json
//                         (person_id looked up from /projects/{id}/people.json)
//   - ListEntitlements -> GET    /projects/{project_id}/people.json
//                         (filtered to {grant.UserExternalID})
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Basecamp email (preferred) or person id
//   - grant.ResourceExternalID -> Basecamp project id
//
// Bearer auth via basecamp.newRequest (BC3 OAuth2 token).

func basecampValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("basecamp: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("basecamp: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *BasecampAccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("User-Agent", "shieldnet360-access (security@uney.com)")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *BasecampAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("basecamp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *BasecampAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := basecampValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email_address": strings.TrimSpace(grant.UserExternalID),
	})
	endpoint := fmt.Sprintf("%s/projects/%s/people/new.json",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("basecamp: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("basecamp: provision status %d: %s", status, string(body))
	}
}

func (c *BasecampAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := basecampValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	personID, err := c.findBasecampPersonID(ctx, cfg, secrets, grant.ResourceExternalID, grant.UserExternalID)
	if err != nil {
		return err
	}
	if personID == "" {
		return nil
	}
	endpoint := fmt.Sprintf("%s/projects/%s/people/%s.json",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)),
		url.PathEscape(personID))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("basecamp: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("basecamp: revoke status %d: %s", status, string(body))
	}
}

func (c *BasecampAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("basecamp: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	projectID := basecampOptionalProjectID(configRaw)
	if projectID == "" {
		return nil, errors.New("basecamp: project_id is required in config for ListEntitlements")
	}
	people, err := c.listBasecampProjectPeople(ctx, cfg, secrets, projectID)
	if err != nil {
		return nil, err
	}
	for i := range people {
		if strings.EqualFold(strings.TrimSpace(people[i].EmailAddress), user) ||
			fmt.Sprintf("%d", people[i].ID) == user {
			role := "member"
			if people[i].Owner {
				role = "owner"
			} else if people[i].Admin {
				role = "admin"
			}
			return []access.Entitlement{{
				ResourceExternalID: projectID,
				Role:               role,
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

func (c *BasecampAccessConnector) findBasecampPersonID(ctx context.Context, cfg Config, secrets Secrets, projectID, identifier string) (string, error) {
	if strings.TrimSpace(projectID) == "" {
		return "", nil
	}
	people, err := c.listBasecampProjectPeople(ctx, cfg, secrets, projectID)
	if err != nil {
		return "", err
	}
	for i := range people {
		if strings.EqualFold(strings.TrimSpace(people[i].EmailAddress), strings.TrimSpace(identifier)) ||
			fmt.Sprintf("%d", people[i].ID) == strings.TrimSpace(identifier) {
			return fmt.Sprintf("%d", people[i].ID), nil
		}
	}
	return "", nil
}

// doRawWithLink mirrors doRaw but also returns the rel="next" URL parsed
// from the RFC 5988 Link header, so paginated collection endpoints can be
// fully walked while preserving the raw status code (callers special-case
// 404 as "not found -> empty").
func (c *BasecampAccessConnector) doRawWithLink(req *http.Request) (int, []byte, string, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, "", fmt.Errorf("basecamp: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nextLinkFromHeader(resp.Header.Get("Link")), nil
}

// basecampPeopleMaxPages bounds the rel="next" Link-header walk in
// listBasecampProjectPeople as defense-in-depth, mirroring
// basecampAuditMaxPages and the audit caps elsewhere in this batch. The
// loop also stops naturally when no next link is returned and checks
// ctx.Err() each iteration; the cap only guards against a misbehaving
// proxy/upstream that keeps issuing next links, which would otherwise
// grow `all` without bound.
const basecampPeopleMaxPages = 200

func (c *BasecampAccessConnector) listBasecampProjectPeople(ctx context.Context, cfg Config, secrets Secrets, projectID string) ([]basecampPerson, error) {
	// Basecamp paginates /projects/{id}/people.json via the RFC 5988
	// Link header. A single GET truncates large project rosters, which
	// would make RevokeAccess/findBasecampPersonID silently miss users on
	// later pages (returning idempotent-success without revoking). Follow
	// rel="next" until absent so the full roster is enumerated.
	nextURL := fmt.Sprintf("%s/projects/%s/people.json",
		c.baseURL(cfg), url.PathEscape(strings.TrimSpace(projectID)))
	var all []basecampPerson
	for page := 0; nextURL != "" && page < basecampPeopleMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return nil, err
		}
		status, body, next, err := c.doRawWithLink(req)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			return nil, nil
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("basecamp: list project people status %d: %s", status, string(body))
		}
		var people []basecampPerson
		if err := json.Unmarshal(body, &people); err != nil {
			return nil, fmt.Errorf("basecamp: decode people: %w", err)
		}
		all = append(all, people...)
		nextURL = next
	}
	return all, nil
}

// basecampOptionalProjectID reads project_id from the raw config map
// without requiring it on the Config struct (which is shared with sync
// paths). Returns an empty string when no project_id is supplied.
func basecampOptionalProjectID(raw map[string]interface{}) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw["project_id"].(string); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := raw["project_id"].(float64); ok {
		return fmt.Sprintf("%d", int64(v))
	}
	return ""
}
