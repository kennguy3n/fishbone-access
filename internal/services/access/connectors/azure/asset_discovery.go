package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Feature E — Azure asset inventory. Azure Resource Manager genuinely exposes
// an inventory API, so the Azure connector implements the optional
// access.AssetDiscoverer capability: a discovery sweep enumerates the
// subscription's compute VMs (onboardable as SSH/RDP PAM targets) and Azure SQL
// servers (onboardable as MSSQL targets) over ARM, reusing the connector's
// existing client-credentials token path (management.azure.com scope) and the
// httpClient/token/url seams so it stays unit-testable against a local server.
// No new SDK is added.

const (
	azureComputeAPIVersion = "2023-07-01"
	azureNetworkAPIVersion = "2023-05-01"
	azureSQLAPIVersion     = "2021-11-01"
	// azureAssetMaxPages bounds the ARM pagination walk so a pathological
	// nextLink loop cannot spin forever, mirroring azureEntitlementsMaxPages.
	azureAssetMaxPages = 50
)

// DiscoverAssets implements access.AssetDiscoverer. It returns the union of
// compute VMs and SQL servers in the configured subscription. A non-nil empty
// slice is returned when the subscription has none (empty-batch contract).
func (c *AzureAccessConnector) DiscoverAssets(ctx context.Context, configRaw, secretsRaw map[string]interface{}) ([]access.DiscoveredAssetSpec, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	client := c.armClient(ctx, cfg, secrets)
	assets := make([]access.DiscoveredAssetSpec, 0, 16)

	vms, err := c.discoverVMs(ctx, client, cfg)
	if err != nil {
		return nil, err
	}
	assets = append(assets, vms...)

	servers, err := c.discoverSQLServers(ctx, client, cfg)
	if err != nil {
		return nil, err
	}
	assets = append(assets, servers...)

	return assets, nil
}

// armGetJSON issues a single signed ARM GET and decodes the JSON body into v.
// It re-anchors nothing (single page); pagination is handled by callers via
// armPagedValues.
func (c *AzureAccessConnector) armGetJSON(ctx context.Context, client httpDoer, absoluteURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, absoluteURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("azure: ARM GET status %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, v)
}

// armNextLink re-anchors an absolute ARM nextLink to the test urlOverride so a
// redirected fake server keeps receiving the walk, mirroring ListEntitlements.
func (c *AzureAccessConnector) armNextLink(nextLink string) string {
	if nextLink == "" {
		return ""
	}
	if c.urlOverride != "" && strings.HasPrefix(nextLink, defaultARMBaseURL) {
		return strings.TrimRight(c.urlOverride, "/") + strings.TrimPrefix(nextLink, defaultARMBaseURL)
	}
	return nextLink
}

// ---- Compute VMs ----

type azureVMListPage struct {
	Value []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			HardwareProfile struct {
				VMSize string `json:"vmSize"`
			} `json:"hardwareProfile"`
			StorageProfile struct {
				OSDisk struct {
					OSType string `json:"osType"`
				} `json:"osDisk"`
			} `json:"storageProfile"`
		} `json:"properties"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

type azureNICListPage struct {
	Value []struct {
		Properties struct {
			VirtualMachine struct {
				ID string `json:"id"`
			} `json:"virtualMachine"`
			IPConfigurations []struct {
				Properties struct {
					PrivateIPAddress string `json:"privateIPAddress"`
				} `json:"properties"`
			} `json:"ipConfigurations"`
		} `json:"properties"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

func (c *AzureAccessConnector) discoverVMs(ctx context.Context, client httpDoer, cfg Config) ([]access.DiscoveredAssetSpec, error) {
	// First map each VM's resource id to its private IP via one network-interface
	// listing — the VM listing itself carries no IP. Bounded by the page cap.
	vmIP, err := c.vmPrivateIPs(ctx, client, cfg)
	if err != nil {
		return nil, err
	}

	out := make([]access.DiscoveredAssetSpec, 0, 16)
	next := c.armURL(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=%s",
		url.PathEscape(cfg.SubscriptionID), azureComputeAPIVersion))
	for page := 0; page < azureAssetMaxPages && next != ""; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var resp azureVMListPage
		if err := c.armGetJSON(ctx, client, next, &resp); err != nil {
			return nil, fmt.Errorf("azure: list virtual machines: %w", err)
		}
		for _, vm := range resp.Value {
			if vm.ID == "" {
				continue
			}
			isWindows := strings.EqualFold(vm.Properties.StorageProfile.OSDisk.OSType, "windows")
			protocol, port := "ssh", "22"
			if isWindows {
				protocol, port = "rdp", "3389"
			}
			address := ""
			if ip := vmIP[strings.ToLower(vm.ID)]; ip != "" {
				address = ip + ":" + port
			}
			out = append(out, access.DiscoveredAssetSpec{
				ExternalID: "azure-vm:" + vm.ID,
				Kind:       access.AssetKindHost,
				Name:       vm.Name,
				Protocol:   protocol,
				Address:    address,
				Region:     vm.Location,
				Metadata: map[string]string{
					"vm_size": vm.Properties.HardwareProfile.VMSize,
					"os_type": vm.Properties.StorageProfile.OSDisk.OSType,
				},
			})
		}
		next = c.armNextLink(resp.NextLink)
	}
	return out, nil
}

// vmPrivateIPs lists the subscription's network interfaces and returns a map of
// lower-cased VM resource id → private IP, so the VM walk can attach a reachable
// address without an O(VMs) per-VM lookup.
func (c *AzureAccessConnector) vmPrivateIPs(ctx context.Context, client httpDoer, cfg Config) (map[string]string, error) {
	ips := map[string]string{}
	next := c.armURL(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Network/networkInterfaces?api-version=%s",
		url.PathEscape(cfg.SubscriptionID), azureNetworkAPIVersion))
	for page := 0; page < azureAssetMaxPages && next != ""; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var resp azureNICListPage
		if err := c.armGetJSON(ctx, client, next, &resp); err != nil {
			return nil, fmt.Errorf("azure: list network interfaces: %w", err)
		}
		for _, nic := range resp.Value {
			vmID := nic.Properties.VirtualMachine.ID
			if vmID == "" {
				continue
			}
			for _, cfgIP := range nic.Properties.IPConfigurations {
				if cfgIP.Properties.PrivateIPAddress != "" {
					ips[strings.ToLower(vmID)] = cfgIP.Properties.PrivateIPAddress
					break
				}
			}
		}
		next = c.armNextLink(resp.NextLink)
	}
	return ips, nil
}

// ---- SQL servers ----

type azureSQLServerListPage struct {
	Value []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			FullyQualifiedDomainName string `json:"fullyQualifiedDomainName"`
			Version                  string `json:"version"`
			State                    string `json:"state"`
		} `json:"properties"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

func (c *AzureAccessConnector) discoverSQLServers(ctx context.Context, client httpDoer, cfg Config) ([]access.DiscoveredAssetSpec, error) {
	out := make([]access.DiscoveredAssetSpec, 0, 8)
	next := c.armURL(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=%s",
		url.PathEscape(cfg.SubscriptionID), azureSQLAPIVersion))
	for page := 0; page < azureAssetMaxPages && next != ""; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var resp azureSQLServerListPage
		if err := c.armGetJSON(ctx, client, next, &resp); err != nil {
			return nil, fmt.Errorf("azure: list sql servers: %w", err)
		}
		for _, srv := range resp.Value {
			if srv.ID == "" {
				continue
			}
			address := srv.Properties.FullyQualifiedDomainName
			if address != "" {
				address += ":1433"
			}
			out = append(out, access.DiscoveredAssetSpec{
				ExternalID: "azure-sql:" + srv.ID,
				Kind:       access.AssetKindDatabase,
				Name:       srv.Name,
				Protocol:   "mssql",
				Address:    address,
				Region:     srv.Location,
				Metadata: map[string]string{
					"fqdn":    srv.Properties.FullyQualifiedDomainName,
					"version": srv.Properties.Version,
					"state":   srv.Properties.State,
				},
			})
		}
		next = c.armNextLink(resp.NextLink)
	}
	return out, nil
}
