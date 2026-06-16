package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func TestDiscoverAssets_VMsAndSQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "Microsoft.Network/networkInterfaces"):
			_, _ = w.Write([]byte(`{"value":[
				{"properties":{"virtualMachine":{"id":"/subscriptions/sub-1/rg/vm-linux"},
				 "ipConfigurations":[{"properties":{"privateIPAddress":"10.0.2.4"}}]}},
				{"properties":{"virtualMachine":{"id":"/subscriptions/sub-1/rg/vm-win"},
				 "ipConfigurations":[{"properties":{"privateIPAddress":"10.0.2.5"}}]}}
			]}`))
		case strings.Contains(r.URL.Path, "Microsoft.Compute/virtualMachines"):
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/sub-1/rg/vm-linux","name":"linux-1","location":"eastus",
				 "properties":{"hardwareProfile":{"vmSize":"Standard_B1s"},"storageProfile":{"osDisk":{"osType":"Linux"}}}},
				{"id":"/subscriptions/sub-1/rg/vm-win","name":"win-1","location":"eastus",
				 "properties":{"hardwareProfile":{"vmSize":"Standard_B2s"},"storageProfile":{"osDisk":{"osType":"Windows"}}}}
			]}`))
		case strings.Contains(r.URL.Path, "Microsoft.Sql/servers"):
			_, _ = w.Write([]byte(`{"value":[
				{"id":"/subscriptions/sub-1/rg/sql-1","name":"orders-sql","location":"eastus",
				 "properties":{"fullyQualifiedDomainName":"orders-sql.database.windows.net","version":"12.0","state":"Ready"}}
			]}`))
		default:
			t.Errorf("unexpected ARM path %q", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.urlOverride = srv.URL
	c.tokenOverride = func(_ context.Context, _ Config, _ Secrets) (string, error) { return "tok", nil }

	assets, err := c.DiscoverAssets(context.Background(), validConfig(), validSecrets())
	if err != nil {
		t.Fatalf("DiscoverAssets: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("got %d assets, want 3 (2 vm + 1 sql)", len(assets))
	}

	byID := map[string]access.DiscoveredAssetSpec{}
	for _, a := range assets {
		byID[a.ExternalID] = a
	}

	linux := byID["azure-vm:/subscriptions/sub-1/rg/vm-linux"]
	if linux.Protocol != "ssh" || linux.Address != "10.0.2.4:22" || linux.Kind != access.AssetKindHost {
		t.Errorf("linux vm = %+v", linux)
	}
	win := byID["azure-vm:/subscriptions/sub-1/rg/vm-win"]
	if win.Protocol != "rdp" || win.Address != "10.0.2.5:3389" {
		t.Errorf("windows vm = %+v", win)
	}
	sql := byID["azure-sql:/subscriptions/sub-1/rg/sql-1"]
	if sql.Protocol != "mssql" || sql.Address != "orders-sql.database.windows.net:1433" || sql.Kind != access.AssetKindDatabase {
		t.Errorf("sql = %+v", sql)
	}
}

// DiscoverAssets must satisfy the optional capability interface.
var _ access.AssetDiscoverer = (*AzureAccessConnector)(nil)
