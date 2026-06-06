// Package aws — GroupSyncer implementation.
//
// AWS IAM models user collections as Groups. Group enumeration uses
// iam:ListGroups (paginated via Marker) and membership resolution uses
// iam:GetGroup?GroupName=... (also paginated, since a group can have
// more than MaxItems members and Get returns up to 1000 per call).
// Both endpoints are query-string form-encoded POSTs to the IAM
// endpoint, signed with SigV4 — reusing the existing callIAM helper.
//
// Note: this is IAM (the long-standing root identity service), not
// Identity Center (the SCIM endpoint composed in scim.go). The two
// surfaces overlap in concept but have distinct APIs.
package aws

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type listGroupsResponse struct {
	XMLName          xml.Name `xml:"ListGroupsResponse"`
	ListGroupsResult struct {
		IsTruncated bool   `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Groups      []struct {
			GroupName  string `xml:"GroupName"`
			GroupID    string `xml:"GroupId"`
			Arn        string `xml:"Arn"`
			Path       string `xml:"Path"`
			CreateDate string `xml:"CreateDate"`
		} `xml:"Groups>member"`
	} `xml:"ListGroupsResult"`
}

type getGroupResponse struct {
	XMLName        xml.Name `xml:"GetGroupResponse"`
	GetGroupResult struct {
		IsTruncated bool   `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Users       []struct {
			UserName string `xml:"UserName"`
			UserID   string `xml:"UserId"`
			Arn      string `xml:"Arn"`
		} `xml:"Users>member"`
	} `xml:"GetGroupResult"`
}

// CountGroups returns the cached IAM Groups quota from
// GetAccountSummary when available, otherwise walks SyncGroups.
// GetAccountSummary's "Groups" entry reflects total IAM groups in
// the account so it's the cheapest counting strategy.
func (c *AWSAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	params := url.Values{}
	params.Set("Action", "GetAccountSummary")
	body, err := c.callIAM(ctx, cfg, secrets, params)
	if err != nil {
		return 0, err
	}
	var result getAccountSummaryResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("aws: decode GetAccountSummary: %w", err)
	}
	for _, e := range result.GetAccountSummaryResult.SummaryMap.Entries {
		if e.Key == "Groups" {
			return e.Value, nil
		}
	}
	// Fall back to a full walk if the summary didn't include Groups.
	total := 0
	if err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	}); err != nil {
		return 0, err
	}
	return total, nil
}

// SyncGroups paginates iam:ListGroups using the Marker cursor and
// surfaces each IAM group as Identity{Type:IdentityTypeGroup,
// ExternalID:GroupName}. IAM's per-group mutation APIs
// (GetGroup, AttachGroupPolicy, AddUserToGroup, …) are all keyed by
// GroupName, not GroupId — so we surface GroupName as the ExternalID
// and stash GroupId in RawData for any consumer that needs the
// immutable identifier. SyncGroupMembers feeds the ExternalID back
// into GetGroup directly, so this keeps the contract internally
// consistent and matches the SyncIdentities convention (UserName as
// ExternalID).
func (c *AWSAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	marker := checkpoint
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		params := url.Values{}
		params.Set("Action", "ListGroups")
		params.Set("MaxItems", "100")
		if marker != "" {
			params.Set("Marker", marker)
		}
		body, err := c.callIAM(ctx, cfg, secrets, params)
		if err != nil {
			return err
		}
		var resp listGroupsResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("aws: decode ListGroups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.ListGroupsResult.Groups))
		for _, g := range resp.ListGroupsResult.Groups {
			identities = append(identities, &access.Identity{
				ExternalID:  g.GroupName,
				Type:        access.IdentityTypeGroup,
				DisplayName: g.GroupName,
				Status:      "active",
				RawData: map[string]interface{}{
					"arn":         g.Arn,
					"path":        g.Path,
					"create_date": g.CreateDate,
					"group_name":  g.GroupName,
					"group_id":    g.GroupID,
				},
			})
		}
		next := ""
		if resp.ListGroupsResult.IsTruncated {
			next = resp.ListGroupsResult.Marker
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		marker = next
	}
}

// SyncGroupMembers paginates iam:GetGroup?GroupName=... and emits the
// member UserName for each member of the group, matching the
// SyncIdentities ExternalID convention (also UserName) so the
// downstream registry can stitch group rows to identity rows by a
// single key. groupExternalID is the IAM GroupName because the
// GetGroup API itself is keyed by name (not GroupId), and the value
// is surfaced through SyncGroups' Identity.ExternalID / RawData
// ["group_name"]. Empty values return an error.
func (c *AWSAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if groupExternalID == "" {
		return errors.New("aws: group external id (GroupName) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	marker := checkpoint
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		params := url.Values{}
		params.Set("Action", "GetGroup")
		params.Set("GroupName", groupExternalID)
		params.Set("MaxItems", strconv.Itoa(100))
		if marker != "" {
			params.Set("Marker", marker)
		}
		body, err := c.callIAM(ctx, cfg, secrets, params)
		if err != nil {
			return err
		}
		var resp getGroupResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("aws: decode GetGroup: %w", err)
		}
		memberIDs := make([]string, 0, len(resp.GetGroupResult.Users))
		for _, u := range resp.GetGroupResult.Users {
			memberIDs = append(memberIDs, u.UserName)
		}
		next := ""
		if resp.GetGroupResult.IsTruncated {
			next = resp.GetGroupResult.Marker
		}
		if err := handler(memberIDs, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		marker = next
	}
}

var _ access.GroupSyncer = (*AWSAccessConnector)(nil)
