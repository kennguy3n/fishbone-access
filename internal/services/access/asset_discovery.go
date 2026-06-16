package access

import "context"

// AssetDiscoverer is an OPTIONAL connector capability (Feature E): a connector
// whose provider exposes a native infrastructure-inventory API implements it to
// enumerate the customer's hosts and databases. It is discovered exactly like
// the other optional capabilities in optional_interfaces.go — a type-assertion
// on AccessConnector — so connectors whose provider has NO inventory surface
// simply do not implement it and the discovery engine skips them. A connector
// must never fabricate an inventory: if it cannot genuinely enumerate, it does
// not satisfy this interface.
//
// DiscoverAssets uses the connector's already-configured credentials (the same
// config/secrets every other capability receives) and returns the live set of
// assets. It performs network I/O and MUST honour ctx cancellation/deadlines.
// Implementations return a non-nil empty slice (not nil) when the account
// genuinely has no assets, mirroring the empty-batch contract the identity and
// group capabilities follow, so downstream JSON consumers see `[]` not `null`.
type AssetDiscoverer interface {
	DiscoverAssets(
		ctx context.Context,
		config map[string]interface{},
		secrets map[string]interface{},
	) ([]DiscoveredAssetSpec, error)
}

// Asset kinds a connector may report. The discovery reconciler uses the kind to
// pick a sensible default protocol when the connector cannot infer one.
const (
	AssetKindHost     = "host"
	AssetKindDatabase = "database"
)

// DiscoveredAssetSpec is the connector-layer DTO for one enumerated asset. The
// discovery service reconciles it into a models.DiscoveredAsset keyed on
// (workspace, source, ExternalID). It carries only non-secret descriptive
// facts; credentials are never part of discovery output.
type DiscoveredAssetSpec struct {
	// ExternalID is the provider-stable identity (e.g. an EC2 instance id
	// "i-0abc123", an RDS DBI resource id, an Azure VM resource id). It is the
	// idempotency key: re-running discovery for the same asset yields the same
	// ExternalID so the reconciler upserts rather than duplicates.
	ExternalID string `json:"external_id"`
	// Kind is AssetKindHost or AssetKindDatabase.
	Kind string `json:"kind"`
	// Name is a friendly display label (instance Name tag, DB identifier).
	Name string `json:"name"`
	// Protocol is the inferred PAM protocol (ssh, rdp, postgres, mysql, mssql,
	// …). Empty when the provider gives no basis to infer one — the reconciler
	// then falls back by Kind.
	Protocol string `json:"protocol"`
	// Address is the reachable endpoint as host or host:port.
	Address string `json:"address"`
	// Region is the cloud region the asset lives in (informational).
	Region string `json:"region"`
	// Metadata carries the remaining non-secret descriptive facts (engine,
	// version, instance type, power state, tags) for the asset detail drawer.
	Metadata map[string]string `json:"metadata,omitempty"`
}
