// Package salesforce — GroupSyncer implementation.
//
// Salesforce models org-level "groups" as PermissionSets. SOQL
// `SELECT Id, Label, Name FROM PermissionSet WHERE IsCustom = true`
// enumerates the roster; `SELECT AssigneeId FROM
// PermissionSetAssignment WHERE PermissionSetId = '...'` returns
// each set's membership. Both endpoints use the same /services/data
// SOQL surface as SyncIdentities, including the queryMore link for
// pagination.
package salesforce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	soqlListPermissionSetsQuery         = "SELECT Id, Name, Label FROM PermissionSet WHERE IsCustom = true"
	soqlListPermissionSetAssignmentsFmt = "SELECT AssigneeId FROM PermissionSetAssignment WHERE PermissionSetId = '%s'"
)

type sfPermissionSetRow struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Label string `json:"Label"`
}

type sfPermissionSetQueryResponse struct {
	TotalSize      int                  `json:"totalSize"`
	Done           bool                 `json:"done"`
	NextRecordsURL string               `json:"nextRecordsUrl,omitempty"`
	Records        []sfPermissionSetRow `json:"records"`
}

type sfAssignmentRow struct {
	AssigneeID string `json:"AssigneeId"`
}

type sfAssignmentQueryResponse struct {
	TotalSize      int               `json:"totalSize"`
	Done           bool              `json:"done"`
	NextRecordsURL string            `json:"nextRecordsUrl,omitempty"`
	Records        []sfAssignmentRow `json:"records"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *SalesforceAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates the PermissionSet SOQL query. The
// checkpoint is the relative nextRecordsUrl (e.g.
// "/services/data/v59.0/query/0r8x...") returned by the prior
// page, so resuming a sync re-uses Salesforce's queryMore cursor.
func (c *SalesforceAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	base := c.instanceBase(cfg)
	var nextURL string
	if checkpoint != "" {
		nextURL = base + checkpoint
	} else {
		q := url.Values{"q": {soqlListPermissionSetsQuery}}
		nextURL = base + "/services/data/" + defaultAPIVersion + "/query?" + q.Encode()
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp sfPermissionSetQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("salesforce: decode permission sets: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Records))
		for _, r := range resp.Records {
			display := r.Label
			if display == "" {
				display = r.Name
			}
			identities = append(identities, &access.Identity{
				ExternalID:  r.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Status:      "active",
			})
		}
		nextCheckpoint := ""
		if !resp.Done && resp.NextRecordsURL != "" {
			nextCheckpoint = resp.NextRecordsURL
		}
		if err := handler(identities, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		nextURL = base + nextCheckpoint
	}
}

// SyncGroupMembers paginates PermissionSetAssignment rows for the
// given PermissionSet ID. Resumes via nextRecordsUrl just like
// SyncGroups.
func (c *SalesforceAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("salesforce: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	base := c.instanceBase(cfg)
	var nextURL string
	if checkpoint != "" {
		nextURL = base + checkpoint
	} else {
		soql := fmt.Sprintf(soqlListPermissionSetAssignmentsFmt, escapeSOQLLiteral(groupExternalID))
		q := url.Values{"q": {soql}}
		nextURL = base + "/services/data/" + defaultAPIVersion + "/query?" + q.Encode()
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp sfAssignmentQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("salesforce: decode permission set assignments: %w", err)
		}
		ids := make([]string, 0, len(resp.Records))
		for _, r := range resp.Records {
			ids = append(ids, r.AssigneeID)
		}
		nextCheckpoint := ""
		if !resp.Done && resp.NextRecordsURL != "" {
			nextCheckpoint = resp.NextRecordsURL
		}
		if err := handler(ids, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		nextURL = base + nextCheckpoint
	}
}

var _ access.GroupSyncer = (*SalesforceAccessConnector)(nil)
