package aws

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type noNetworkRoundTripper struct{}

func (noNetworkRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("network call attempted")
}

func validConfig() map[string]interface{} {
	return map[string]interface{}{"aws_region": "us-east-1", "aws_account_id": "123456789012"}
}

func validSecrets() map[string]interface{} {
	return map[string]interface{}{
		"aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
}

func TestValidate_HappyPath(t *testing.T) {
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsBadRegion(t *testing.T) {
	c := New()
	if err := c.Validate(context.Background(), map[string]interface{}{"aws_region": "abc"}, validSecrets()); err == nil {
		t.Error("bad region: want error")
	}
	if err := c.Validate(context.Background(), map[string]interface{}{"aws_region": "us-east-1", "aws_account_id": "123"}, validSecrets()); err == nil {
		t.Error("bad account_id: want error")
	}
	if err := c.Validate(context.Background(), validConfig(), map[string]interface{}{}); err == nil {
		t.Error("missing secrets")
	}
}

func TestLooksLikeAWSRegion(t *testing.T) {
	cases := []struct {
		region string
		want   bool
	}{
		// Existing geos
		{"us-east-1", true},
		{"eu-west-2", true},
		{"ap-southeast-1", true},
		{"ca-central-1", true},
		{"sa-east-1", true},
		{"af-south-1", true},
		{"me-central-1", true},
		{"cn-north-1", true},
		// Newer geos that the old hardcoded allowlist rejected.
		{"il-central-1", true},
		// GovCloud still passes — its actual prefix is "us".
		{"us-gov-west-1", true},
		{"us-gov-east-1", true},
		// Bogus values must still be rejected.
		{"abc", false},
		{"us-east", false},
		{"", false},
		{"x-east-1", false},          // 1-letter prefix
		{"longprefix-east-1", false}, // >6-letter prefix
		{"US-EAST-1", false},         // uppercase
		{"u1-east-1", false},         // digit in prefix
	}
	for _, tc := range cases {
		if got := looksLikeAWSRegion(tc.region); got != tc.want {
			t.Errorf("looksLikeAWSRegion(%q) = %v; want %v", tc.region, got, tc.want)
		}
	}
}

func TestValidate_PureLocal(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = noNetworkRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
	if err := New().Validate(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRegistryIntegration(t *testing.T) {
	if got, _ := access.GetAccessConnector(ProviderName); got == nil {
		t.Fatal("not registered")
	}
}

func TestSigV4_AddsAuthorizationHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/") {
			t.Errorf("missing/wrong Authorization: %q", auth)
		}
		if r.Header.Get("X-Amz-Date") == "" {
			t.Error("missing X-Amz-Date")
		}
		if r.Header.Get("X-Amz-Content-Sha256") == "" {
			t.Error("missing X-Amz-Content-Sha256")
		}
		w.Write([]byte(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>Users</key><value>5</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func TestConnect_FailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	if err := c.Connect(context.Background(), validConfig(), validSecrets()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("Connect err = %v; want 403", err)
	}
}

func TestSyncIdentities_PaginatesViaMarker(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("Action") != "ListUsers" {
			t.Errorf("Action = %q", r.Form.Get("Action"))
		}
		if page == 1 {
			w.Write([]byte(`<ListUsersResponse><ListUsersResult><IsTruncated>true</IsTruncated><Marker>NEXT</Marker><Users><member><UserName>alice</UserName><UserId>AIDA1</UserId><Arn>arn:aws:iam::123:user/alice</Arn></member></Users></ListUsersResult></ListUsersResponse>`))
			return
		}
		if r.Form.Get("Marker") != "NEXT" {
			t.Errorf("Marker = %q", r.Form.Get("Marker"))
		}
		w.Write([]byte(`<ListUsersResponse><ListUsersResult><IsTruncated>false</IsTruncated><Users><member><UserName>bob</UserName><UserId>AIDA2</UserId></member></Users></ListUsersResult></ListUsersResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	var got []*access.Identity
	err := c.SyncIdentities(context.Background(), validConfig(), validSecrets(), "", func(b []*access.Identity, _ string) error {
		got = append(got, b...)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2", len(got))
	}
}

func TestCount_ReadsUsersFromSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>Users</key><value>17</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	n, err := c.CountIdentities(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("CountIdentities: %v", err)
	}
	if n != 17 {
		t.Errorf("count = %d; want 17", n)
	}
}

func TestGetCredentialsMetadata_LooksUpKeyAge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata><member><AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId><Status>Active</Status><CreateDate>2024-01-01T00:00:00Z</CreateDate><UserName>devops</UserName></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	md, err := c.GetCredentialsMetadata(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if md["access_key_status"] != "Active" {
		t.Errorf("status = %v", md["access_key_status"])
	}
	if md["iam_user_name"] != "devops" {
		t.Errorf("iam_user_name = %v", md["iam_user_name"])
	}
}

func TestProvisionAccess_AttachUserPolicy(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"ok", `<AttachUserPolicyResponse/>`},
		{"already_attached_idempotent", `<ErrorResponse><Error><Code>EntityAlreadyExists</Code><Message>policy already attached</Message></Error></ErrorResponse>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenAction, seenUser, seenPolicy string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				seenAction = r.Form.Get("Action")
				seenUser = r.Form.Get("UserName")
				seenPolicy = r.Form.Get("PolicyArn")
				if strings.Contains(tc.body, "ErrorResponse") {
					w.WriteHeader(http.StatusBadRequest)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.httpClient = func() httpDoer { return srv.Client() }
			c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
			err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "alice", ResourceExternalID: "arn:aws:iam::aws:policy/ReadOnlyAccess",
			})
			if err != nil {
				t.Fatalf("ProvisionAccess: %v", err)
			}
			if seenAction != "AttachUserPolicy" || seenUser != "alice" || seenPolicy != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
				t.Fatalf("form = %s/%s/%s", seenAction, seenUser, seenPolicy)
			}
		})
	}
}

func TestProvisionAccess_OtherErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>user does not exist</Message></Error></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	err := c.ProvisionAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "ghost", ResourceExternalID: "arn:aws:iam::aws:policy/ReadOnlyAccess",
	})
	if err == nil || !strings.Contains(err.Error(), "NoSuchEntity") {
		t.Fatalf("expected NoSuchEntity error, got %v", err)
	}
}

func TestRevokeAccess_DetachUserPolicy(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"ok", http.StatusOK, `<DetachUserPolicyResponse/>`},
		{"not_attached_idempotent", http.StatusNotFound, `<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seenAction string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				seenAction = r.Form.Get("Action")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			c := New()
			c.urlOverride = srv.URL
			c.httpClient = func() httpDoer { return srv.Client() }
			c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
			err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
				UserExternalID: "alice", ResourceExternalID: "arn:aws:iam::aws:policy/ReadOnlyAccess",
			})
			if err != nil {
				t.Fatalf("RevokeAccess: %v", err)
			}
			if seenAction != "DetachUserPolicy" {
				t.Fatalf("action = %q", seenAction)
			}
		})
	}
}

func TestRevokeAccess_OtherErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	err := c.RevokeAccess(context.Background(), validConfig(), validSecrets(), access.AccessGrant{
		UserExternalID: "alice", ResourceExternalID: "arn:aws:iam::aws:policy/ReadOnlyAccess",
	})
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("expected AccessDenied error, got %v", err)
	}
}

func TestListEntitlements_PaginatesAttachedPolicies(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("Action") != "ListAttachedUserPolicies" {
			t.Errorf("Action = %q", r.Form.Get("Action"))
		}
		if page == 1 {
			_, _ = w.Write([]byte(`<ListAttachedUserPoliciesResponse><ListAttachedUserPoliciesResult><IsTruncated>true</IsTruncated><Marker>NEXT</Marker><AttachedPolicies><member><PolicyName>ReadOnlyAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/ReadOnlyAccess</PolicyArn></member></AttachedPolicies></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>`))
			return
		}
		if r.Form.Get("Marker") != "NEXT" {
			t.Errorf("Marker = %q", r.Form.Get("Marker"))
		}
		_, _ = w.Write([]byte(`<ListAttachedUserPoliciesResponse><ListAttachedUserPoliciesResult><IsTruncated>false</IsTruncated><AttachedPolicies><member><PolicyName>S3FullAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/S3FullAccess</PolicyArn></member></AttachedPolicies></ListAttachedUserPoliciesResult></ListAttachedUserPoliciesResponse>`))
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	got, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice")
	if err != nil {
		t.Fatalf("ListEntitlements: %v", err)
	}
	if len(got) != 2 || got[0].Role != "ReadOnlyAccess" || got[1].Role != "S3FullAccess" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Source != "direct" {
		t.Fatalf("source = %q", got[0].Source)
	}
}

func TestListEntitlements_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := c.ListEntitlements(context.Background(), validConfig(), validSecrets(), "alice"); err == nil {
		t.Fatal("expected error on 403")
	}
}
