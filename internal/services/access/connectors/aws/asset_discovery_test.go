package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	ec2DescribeXML = `<DescribeInstancesResponse>
  <reservationSet>
    <item>
      <instancesSet>
        <item>
          <instanceId>i-aaa</instanceId>
          <privateIpAddress>10.0.1.10</privateIpAddress>
          <instanceType>t3.micro</instanceType>
          <instanceState><name>running</name></instanceState>
          <placement><availabilityZone>us-east-1a</availabilityZone></placement>
          <tagSet><item><key>Name</key><value>web-1</value></item></tagSet>
        </item>
        <item>
          <instanceId>i-bbb</instanceId>
          <privateIpAddress>10.0.1.11</privateIpAddress>
          <platform>windows</platform>
          <instanceState><name>running</name></instanceState>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>`

	rdsDescribeXML = `<DescribeDBInstancesResponse>
  <DescribeDBInstancesResult>
    <DBInstances>
      <DBInstance>
        <DBInstanceIdentifier>orders-prod</DBInstanceIdentifier>
        <DbiResourceId>db-ABC123</DbiResourceId>
        <Engine>postgres</Engine>
        <DBInstanceStatus>available</DBInstanceStatus>
        <Endpoint><Address>orders.abc.us-east-1.rds.amazonaws.com</Address><Port>5432</Port></Endpoint>
      </DBInstance>
    </DBInstances>
  </DescribeDBInstancesResult>
</DescribeDBInstancesResponse>`
)

func TestDiscoverAssets_EC2AndRDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.Form.Get("Action") {
		case "DescribeInstances":
			_, _ = w.Write([]byte(ec2DescribeXML))
		case "DescribeDBInstances":
			_, _ = w.Write([]byte(rdsDescribeXML))
		default:
			t.Errorf("unexpected Action %q", r.Form.Get("Action"))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	assets, err := c.DiscoverAssets(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("DiscoverAssets: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("got %d assets, want 3 (2 ec2 + 1 rds)", len(assets))
	}

	byID := map[string]access.DiscoveredAssetSpec{}
	for _, a := range assets {
		byID[a.ExternalID] = a
	}

	linux := byID["ec2:i-aaa"]
	if linux.Protocol != "ssh" || linux.Address != "10.0.1.10:22" || linux.Name != "web-1" {
		t.Errorf("linux ec2 = %+v", linux)
	}
	if linux.Kind != access.AssetKindHost {
		t.Errorf("ec2 kind = %q", linux.Kind)
	}

	win := byID["ec2:i-bbb"]
	if win.Protocol != "rdp" || win.Address != "10.0.1.11:3389" {
		t.Errorf("windows ec2 = %+v", win)
	}

	db := byID["rds:db-ABC123"]
	if db.Protocol != "postgres" || db.Address != "orders.abc.us-east-1.rds.amazonaws.com:5432" || db.Kind != access.AssetKindDatabase {
		t.Errorf("rds = %+v", db)
	}
}

// TestDiscoverAssets_Paginates verifies the EC2 NextToken and RDS Marker walks
// collect assets across every page (not just the first) and echo the page token
// back on the follow-up request, mirroring TestSyncIdentities_PaginatesViaMarker.
func TestDiscoverAssets_Paginates(t *testing.T) {
	const (
		ec2Page1 = `<DescribeInstancesResponse>
  <reservationSet><item><instancesSet>
    <item><instanceId>i-page1</instanceId><privateIpAddress>10.0.1.10</privateIpAddress><instanceState><name>running</name></instanceState></item>
  </instancesSet></item></reservationSet>
  <nextToken>EC2TOKEN2</nextToken>
</DescribeInstancesResponse>`
		ec2Page2 = `<DescribeInstancesResponse>
  <reservationSet><item><instancesSet>
    <item><instanceId>i-page2</instanceId><privateIpAddress>10.0.1.11</privateIpAddress><instanceState><name>running</name></instanceState></item>
  </instancesSet></item></reservationSet>
</DescribeInstancesResponse>`
		rdsPage1 = `<DescribeDBInstancesResponse><DescribeDBInstancesResult>
  <Marker>RDSMARKER2</Marker>
  <DBInstances><DBInstance>
    <DBInstanceIdentifier>db-page1</DBInstanceIdentifier><DbiResourceId>db-P1</DbiResourceId><Engine>postgres</Engine>
    <Endpoint><Address>p1.rds.amazonaws.com</Address><Port>5432</Port></Endpoint>
  </DBInstance></DBInstances>
</DescribeDBInstancesResult></DescribeDBInstancesResponse>`
		rdsPage2 = `<DescribeDBInstancesResponse><DescribeDBInstancesResult>
  <DBInstances><DBInstance>
    <DBInstanceIdentifier>db-page2</DBInstanceIdentifier><DbiResourceId>db-P2</DbiResourceId><Engine>mysql</Engine>
    <Endpoint><Address>p2.rds.amazonaws.com</Address><Port>3306</Port></Endpoint>
  </DBInstance></DBInstances>
</DescribeDBInstancesResult></DescribeDBInstancesResponse>`
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.Form.Get("Action") {
		case "DescribeInstances":
			switch tok := r.Form.Get("NextToken"); tok {
			case "":
				_, _ = w.Write([]byte(ec2Page1))
			case "EC2TOKEN2":
				_, _ = w.Write([]byte(ec2Page2))
			default:
				t.Errorf("unexpected EC2 NextToken %q", tok)
			}
		case "DescribeDBInstances":
			switch m := r.Form.Get("Marker"); m {
			case "":
				_, _ = w.Write([]byte(rdsPage1))
			case "RDSMARKER2":
				_, _ = w.Write([]byte(rdsPage2))
			default:
				t.Errorf("unexpected RDS Marker %q", m)
			}
		default:
			t.Errorf("unexpected Action %q", r.Form.Get("Action"))
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.httpClient = func() httpDoer { return srv.Client() }
	c.timeOverride = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	assets, err := c.DiscoverAssets(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("DiscoverAssets: %v", err)
	}

	got := map[string]bool{}
	for _, a := range assets {
		got[a.ExternalID] = true
	}
	for _, want := range []string{"ec2:i-page1", "ec2:i-page2", "rds:db-P1", "rds:db-P2"} {
		if !got[want] {
			t.Errorf("missing paginated asset %q; got %v", want, got)
		}
	}
	if len(assets) != 4 {
		t.Fatalf("got %d assets, want 4 (2 ec2 pages + 2 rds pages)", len(assets))
	}
}

func TestRDSEngineProtocol(t *testing.T) {
	cases := map[string]string{
		"postgres":        "postgres",
		"aurora-postgres": "postgres",
		"mysql":           "mysql",
		"mariadb":         "mysql",
		"aurora-mysql":    "mysql",
		"sqlserver- se":   "mssql",
		"oracle-ee":       "",
	}
	for engine, want := range cases {
		if got := rdsEngineProtocol(engine); got != want {
			t.Errorf("rdsEngineProtocol(%q) = %q, want %q", engine, got, want)
		}
	}
}

// DiscoverAssets must satisfy the optional capability interface.
var _ access.AssetDiscoverer = (*AWSAccessConnector)(nil)
