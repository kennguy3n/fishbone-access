package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Feature E — AWS asset inventory. The AWS connector genuinely exposes an
// infrastructure-inventory API, so it implements the optional
// access.AssetDiscoverer capability: a discovery sweep enumerates the account's
// EC2 instances (onboardable as SSH/RDP PAM targets) and RDS databases
// (onboardable as Postgres/MySQL/MSSQL targets) using the SAME SigV4-signed
// Query API + credentials the rest of the connector already uses. No new SDK is
// pulled in — this reuses the hand-rolled signRequestSigV4 and the connector's
// httpClient/time seams so it stays unit-testable against a local server.

const (
	ec2APIVersion = "2016-11-15"
	rdsAPIVersion = "2014-10-31"
	// awsAssetMaxPages bounds the EC2 NextToken / RDS Marker pagination walk so
	// a pathological token loop cannot spin forever, mirroring azureAssetMaxPages
	// in the Azure connector. 50 pages covers 50k EC2 (1000/page) and 5k RDS
	// (100/page), far beyond any single SME account.
	awsAssetMaxPages = 50
)

// DiscoverAssets implements access.AssetDiscoverer. It returns the union of EC2
// instances and RDS databases visible to the configured credentials in the
// connector's region. A non-nil empty slice is returned when the account has
// no assets (empty-batch contract).
func (c *AWSAccessConnector) DiscoverAssets(ctx context.Context, configRaw, secretsRaw map[string]interface{}) ([]access.DiscoveredAssetSpec, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	assets := make([]access.DiscoveredAssetSpec, 0, 16)

	hosts, err := c.discoverEC2(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	assets = append(assets, hosts...)

	dbs, err := c.discoverRDS(ctx, cfg, secrets)
	if err != nil {
		return nil, err
	}
	assets = append(assets, dbs...)

	return assets, nil
}

// regionalEndpoint builds the SigV4 host for a regional service, honouring the
// test urlOverride so the sweep is exercisable against a local fake. Production
// uses https://<service>.<region>.amazonaws.com/.
func (c *AWSAccessConnector) regionalEndpoint(service, region string) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return fmt.Sprintf("https://%s.%s.amazonaws.com/", service, region)
}

// callQuery issues a signed AWS Query-protocol POST for a regional service and
// returns the raw XML body. Mirrors callIAM but is parameterised by service +
// region + endpoint so EC2 and RDS share one signed-request path.
func (c *AWSAccessConnector) callQuery(ctx context.Context, cfg Config, secrets Secrets, service string, params url.Values) ([]byte, error) {
	body := params.Encode()
	endpoint := c.regionalEndpoint(service, cfg.Region)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/xml")
	if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, cfg.Region, service, c.now()); err != nil {
		return nil, fmt.Errorf("aws: sign %s: %w", service, err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws: %s %s: %w", service, params.Get("Action"), err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("aws: %s %s: status %d: %s", service, params.Get("Action"), resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// ---- EC2 ----

type ec2DescribeInstancesResponse struct {
	XMLName xml.Name `xml:"DescribeInstancesResponse"`
	// NextToken is present when the result set spans multiple pages; EC2
	// DescribeInstances returns at most 1000 instances per page.
	NextToken      string `xml:"nextToken"`
	ReservationSet struct {
		Items []struct {
			InstancesSet struct {
				Items []ec2Instance `xml:"item"`
			} `xml:"instancesSet"`
		} `xml:"item"`
	} `xml:"reservationSet"`
}

type ec2Instance struct {
	InstanceID       string `xml:"instanceId"`
	PrivateIPAddress string `xml:"privateIpAddress"`
	IPAddress        string `xml:"ipAddress"`
	InstanceType     string `xml:"instanceType"`
	Platform         string `xml:"platform"`
	PlatformDetails  string `xml:"platformDetails"`
	Architecture     string `xml:"architecture"`
	InstanceState    struct {
		Name string `xml:"name"`
	} `xml:"instanceState"`
	Placement struct {
		AvailabilityZone string `xml:"availabilityZone"`
	} `xml:"placement"`
	TagSet struct {
		Items []struct {
			Key   string `xml:"key"`
			Value string `xml:"value"`
		} `xml:"item"`
	} `xml:"tagSet"`
}

func (c *AWSAccessConnector) discoverEC2(ctx context.Context, cfg Config, secrets Secrets) ([]access.DiscoveredAssetSpec, error) {
	out := make([]access.DiscoveredAssetSpec, 0, 16)
	// EC2 DescribeInstances pages via NextToken (max 1000 instances/page). Walk
	// every page so accounts with large fleets do not silently lose targets
	// beyond the first page, bounded by awsAssetMaxPages.
	token := ""
	for page := 0; page < awsAssetMaxPages; page++ {
		params := url.Values{}
		params.Set("Action", "DescribeInstances")
		params.Set("Version", ec2APIVersion)
		// Only running/pending instances are reachable targets; a terminated box is
		// not onboardable. Filter server-side so a large fleet does not page back
		// stopped/terminated noise.
		params.Set("Filter.1.Name", "instance-state-name")
		params.Set("Filter.1.Value.1", "running")
		params.Set("Filter.1.Value.2", "pending")
		if token != "" {
			params.Set("NextToken", token)
		}

		body, err := c.callQuery(ctx, cfg, secrets, "ec2", params)
		if err != nil {
			return nil, err
		}
		var resp ec2DescribeInstancesResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("aws: decode DescribeInstances: %w", err)
		}
		for _, res := range resp.ReservationSet.Items {
			for _, inst := range res.InstancesSet.Items {
				if inst.InstanceID == "" {
					continue
				}
				// Prefer the private address: discovery onboards targets reached
				// through an in-network agent, not over the public internet.
				host := inst.PrivateIPAddress
				if host == "" {
					host = inst.IPAddress
				}
				isWindows := strings.EqualFold(inst.Platform, "windows") ||
					strings.Contains(strings.ToLower(inst.PlatformDetails), "windows")
				protocol, port := "ssh", "22"
				if isWindows {
					protocol, port = "rdp", "3389"
				}
				address := host
				if host != "" {
					address = host + ":" + port
				}
				name := tagValue(inst.TagSet.Items, "Name")
				if name == "" {
					name = inst.InstanceID
				}
				meta := map[string]string{
					"instance_type": inst.InstanceType,
					"state":         inst.InstanceState.Name,
					"az":            inst.Placement.AvailabilityZone,
				}
				if inst.Architecture != "" {
					meta["architecture"] = inst.Architecture
				}
				if inst.PlatformDetails != "" {
					meta["platform"] = inst.PlatformDetails
				}
				out = append(out, access.DiscoveredAssetSpec{
					ExternalID: "ec2:" + inst.InstanceID,
					Kind:       access.AssetKindHost,
					Name:       name,
					Protocol:   protocol,
					Address:    address,
					Region:     cfg.Region,
					Metadata:   meta,
				})
			}
		}
		if resp.NextToken == "" {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

func tagValue(items []struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}, key string) string {
	for _, t := range items {
		if t.Key == key {
			return t.Value
		}
	}
	return ""
}

// ---- RDS ----

type rdsDescribeDBInstancesResponse struct {
	XMLName xml.Name `xml:"DescribeDBInstancesResponse"`
	Result  struct {
		// Marker is present when the result set spans multiple pages; RDS
		// DescribeDBInstances returns at most 100 instances per page.
		Marker      string `xml:"Marker"`
		DBInstances struct {
			Items []rdsDBInstance `xml:"DBInstance"`
		} `xml:"DBInstances"`
	} `xml:"DescribeDBInstancesResult"`
}

type rdsDBInstance struct {
	DBInstanceIdentifier string `xml:"DBInstanceIdentifier"`
	DbiResourceID        string `xml:"DbiResourceId"`
	Engine               string `xml:"Engine"`
	EngineVersion        string `xml:"EngineVersion"`
	DBInstanceStatus     string `xml:"DBInstanceStatus"`
	DBInstanceClass      string `xml:"DBInstanceClass"`
	Endpoint             struct {
		Address string `xml:"Address"`
		Port    int    `xml:"Port"`
	} `xml:"Endpoint"`
}

func (c *AWSAccessConnector) discoverRDS(ctx context.Context, cfg Config, secrets Secrets) ([]access.DiscoveredAssetSpec, error) {
	out := make([]access.DiscoveredAssetSpec, 0, 8)
	// RDS DescribeDBInstances pages via Marker (max 100 instances/page). Walk
	// every page so accounts with many databases do not silently lose targets
	// beyond the first page, bounded by awsAssetMaxPages.
	marker := ""
	for page := 0; page < awsAssetMaxPages; page++ {
		params := url.Values{}
		params.Set("Action", "DescribeDBInstances")
		params.Set("Version", rdsAPIVersion)
		if marker != "" {
			params.Set("Marker", marker)
		}

		body, err := c.callQuery(ctx, cfg, secrets, "rds", params)
		if err != nil {
			return nil, err
		}
		var resp rdsDescribeDBInstancesResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("aws: decode DescribeDBInstances: %w", err)
		}
		for _, db := range resp.Result.DBInstances.Items {
			if db.DBInstanceIdentifier == "" {
				continue
			}
			protocol := rdsEngineProtocol(db.Engine)
			address := db.Endpoint.Address
			if address != "" && db.Endpoint.Port > 0 {
				address = fmt.Sprintf("%s:%d", db.Endpoint.Address, db.Endpoint.Port)
			}
			// The DbiResourceId is immutable across renames; prefer it as the
			// idempotency key and fall back to the identifier when absent.
			ext := db.DbiResourceID
			if ext == "" {
				ext = db.DBInstanceIdentifier
			}
			out = append(out, access.DiscoveredAssetSpec{
				ExternalID: "rds:" + ext,
				Kind:       access.AssetKindDatabase,
				Name:       db.DBInstanceIdentifier,
				Protocol:   protocol,
				Address:    address,
				Region:     cfg.Region,
				Metadata: map[string]string{
					"engine":         db.Engine,
					"engine_version": db.EngineVersion,
					"status":         db.DBInstanceStatus,
					"instance_class": db.DBInstanceClass,
				},
			})
		}
		if resp.Result.Marker == "" {
			break
		}
		marker = resp.Result.Marker
	}
	return out, nil
}

// rdsEngineProtocol maps an RDS engine string to the PAM protocol used to
// onboard it. Unknown engines return "" so the reconciler falls back by kind.
func rdsEngineProtocol(engine string) string {
	e := strings.ToLower(engine)
	switch {
	case strings.Contains(e, "postgres"):
		return "postgres"
	case strings.Contains(e, "mysql"), strings.Contains(e, "mariadb"), strings.Contains(e, "aurora") && !strings.Contains(e, "postgres"):
		return "mysql"
	case strings.Contains(e, "sqlserver"):
		return "mssql"
	default:
		return ""
	}
}
