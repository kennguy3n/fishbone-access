package aws

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func readIAMAction(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	return params
}

func TestAWS_SyncGroups_HappyPathTwoPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := readIAMAction(t, r)
		if params.Get("Action") != "ListGroups" {
			t.Fatalf("unexpected action %q", params.Get("Action"))
		}
		marker := params.Get("Marker")
		w.Header().Set("Content-Type", "application/xml")
		switch marker {
		case "":
			_, _ = w.Write([]byte(`<ListGroupsResponse><ListGroupsResult><IsTruncated>true</IsTruncated><Marker>page2</Marker><Groups><member><GroupName>devs</GroupName><GroupId>AGPAEX1</GroupId><Arn>arn:aws:iam::1:group/devs</Arn><Path>/</Path><CreateDate>2024-01-01T00:00:00Z</CreateDate></member></Groups></ListGroupsResult></ListGroupsResponse>`))
		case "page2":
			_, _ = w.Write([]byte(`<ListGroupsResponse><ListGroupsResult><IsTruncated>false</IsTruncated><Groups><member><GroupName>ops</GroupName><GroupId>AGPAEX2</GroupId><Arn>arn:aws:iam::1:group/ops</Arn><Path>/</Path><CreateDate>2024-02-02T00:00:00Z</CreateDate></member></Groups></ListGroupsResult></ListGroupsResponse>`))
		default:
			t.Fatalf("unexpected marker %q", marker)
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var groups []*access.Identity
	if err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(b []*access.Identity, _ string) error {
			groups = append(groups, b...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d; want 2", len(groups))
	}
	if groups[0].ExternalID != "devs" || groups[1].ExternalID != "ops" {
		t.Errorf("external ids: %s,%s", groups[0].ExternalID, groups[1].ExternalID)
	}
	if groups[0].DisplayName != "devs" {
		t.Errorf("display: %s", groups[0].DisplayName)
	}
}

func TestAWS_SyncGroupMembers_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := readIAMAction(t, r)
		if params.Get("Action") != "GetGroup" {
			t.Fatalf("unexpected action %q", params.Get("Action"))
		}
		if params.Get("GroupName") != "devs" {
			t.Fatalf("unexpected GroupName %q", params.Get("GroupName"))
		}
		_, _ = w.Write([]byte(`<GetGroupResponse><GetGroupResult><IsTruncated>false</IsTruncated><Users><member><UserName>alice</UserName><UserId>AIDA1</UserId><Arn>arn:aws:iam::1:user/alice</Arn></member><member><UserName>bob</UserName><UserId>AIDA2</UserId><Arn>arn:aws:iam::1:user/bob</Arn></member></Users></GetGroupResult></GetGroupResponse>`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "devs", "",
		func(batch []string, _ string) error {
			ids = append(ids, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if strings.Join(ids, ",") != "alice,bob" {
		t.Errorf("ids = %v; want [alice bob]", ids)
	}
}

func TestAWS_SyncGroupMembers_Paginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := readIAMAction(t, r)
		marker := params.Get("Marker")
		switch marker {
		case "":
			_, _ = w.Write([]byte(`<GetGroupResponse><GetGroupResult><IsTruncated>true</IsTruncated><Marker>m2</Marker><Users><member><UserName>u1</UserName><UserId>AIDA1</UserId></member></Users></GetGroupResult></GetGroupResponse>`))
		case "m2":
			_, _ = w.Write([]byte(`<GetGroupResponse><GetGroupResult><IsTruncated>false</IsTruncated><Users><member><UserName>u2</UserName><UserId>AIDA2</UserId></member></Users></GetGroupResult></GetGroupResponse>`))
		}
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	var ids []string
	if err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "devs", "",
		func(batch []string, _ string) error {
			ids = append(ids, batch...)
			return nil
		}); err != nil {
		t.Fatalf("SyncGroupMembers: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("ids = %d; want 2", len(ids))
	}
}

func TestAWS_SyncGroupMembers_MissingName(t *testing.T) {
	c := New()
	err := c.SyncGroupMembers(context.Background(), validConfig(), validSecrets(), "", "",
		func(_ []string, _ string) error { return nil })
	if err == nil {
		t.Error("want error for empty group name")
	}
}

func TestAWS_CountGroups_UsesSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := readIAMAction(t, r)
		if params.Get("Action") != "GetAccountSummary" {
			t.Fatalf("unexpected action %q", params.Get("Action"))
		}
		_, _ = w.Write([]byte(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>Groups</key><value>42</value></entry><entry><key>Users</key><value>100</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	n, err := c.CountGroups(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountGroups: %v", err)
	}
	if n != 42 {
		t.Errorf("n = %d; want 42", n)
	}
}

func TestAWS_SyncGroups_ServerErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("<ErrorResponse><Error><Code>ServerFault</Code></Error></ErrorResponse>"))
	}))
	defer srv.Close()
	c := New()
	c.urlOverride = srv.URL
	err := c.SyncGroups(context.Background(), validConfig(), validSecrets(), "",
		func(_ []*access.Identity, _ string) error { return nil })
	if err == nil {
		t.Error("want error for 500")
	}
}

func TestAWS_SatisfiesGroupSyncerInterface(t *testing.T) {
	var _ access.GroupSyncer = New()
}
