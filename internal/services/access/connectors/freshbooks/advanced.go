package freshbooks

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

// advanced-capability mapping for FreshBooks:
//
//   - ProvisionAccess  -> PUT /accounting/account/{id}/users/staffs/{staff_id}
//                         body: {"staff":{"role":"<role>"}}
//   - RevokeAccess     -> PUT /accounting/account/{id}/users/staffs/{staff_id}
//                         body: {"staff":{"role":"<role>","vis_state":1}}
//                         (FreshBooks-idiomatic soft-delete on the staff endpoint)
//   - ListEntitlements -> GET /accounting/account/{id}/users/staffs
//                         emits one entitlement per staff member, exposing the
//                         FreshBooks role as Entitlement.ResourceExternalID so the
//                         (UserExternalID, ResourceExternalID) tuple round-trips.
//
// AccessGrant maps:
//   - grant.UserExternalID     -> FreshBooks staff_id
//   - grant.ResourceExternalID -> FreshBooks role identifier (e.g. "managed_user")
//
// Bearer auth via FreshBooksAccessConnector.newRequest /
// FreshBooksAccessConnector.newJSONRequest.

func freshbooksValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("freshbooks: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("freshbooks: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *FreshBooksAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("freshbooks: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *FreshBooksAccessConnector) staffURL(cfg Config, staffID string) string {
	return fmt.Sprintf("%s/accounting/account/%s/users/staffs/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.AccountID)),
		url.PathEscape(strings.TrimSpace(staffID)))
}

// staffPayload is the FreshBooks-idiomatic body envelope for staff updates.
// Role carries the grant.ResourceExternalID so reconciliation between
// ProvisionAccess and ListEntitlements is sound; VisState=1 marks the staff
// row as deleted (the FreshBooks soft-delete convention on this endpoint).
type staffPayload struct {
	Staff staffPayloadInner `json:"staff"`
}

type staffPayloadInner struct {
	Role     string `json:"role,omitempty"`
	VisState int    `json:"vis_state,omitempty"`
}

func (c *FreshBooksAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body interface{}) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("freshbooks: marshal request body: %w", err)
		}
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Api-Version", "alpha")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *FreshBooksAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := freshbooksValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := staffPayload{Staff: staffPayloadInner{Role: strings.TrimSpace(grant.ResourceExternalID)}}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, c.staffURL(cfg, grant.UserExternalID), payload)
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
		return fmt.Errorf("freshbooks: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("freshbooks: provision status %d: %s", status, string(body))
	}
}

func (c *FreshBooksAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := freshbooksValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload := staffPayload{Staff: staffPayloadInner{
		Role:     strings.TrimSpace(grant.ResourceExternalID),
		VisState: 1,
	}}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, c.staffURL(cfg, grant.UserExternalID), payload)
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
		return fmt.Errorf("freshbooks: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("freshbooks: revoke status %d: %s", status, string(body))
	}
}

func (c *FreshBooksAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("freshbooks: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/accounting/account/%s/users/staffs",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.AccountID)))
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
		return nil, fmt.Errorf("freshbooks: list staffs status %d: %s", status, string(body))
	}
	var envelope struct {
		Response struct {
			Result struct {
				Staff []struct {
					ID   interface{} `json:"id"`
					Role string      `json:"role"`
				} `json:"staff"`
			} `json:"result"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("freshbooks: decode staff: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Response.Result.Staff))
	for _, s := range envelope.Response.Result.Staff {
		id := strings.TrimSpace(fmt.Sprintf("%v", s.ID))
		if id == "" || id != user {
			continue
		}
		role := strings.TrimSpace(s.Role)
		if role == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
