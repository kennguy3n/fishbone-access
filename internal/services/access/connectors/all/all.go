// Package all blank-imports every connector package so their init() side
// effects register each provider with the process-global access registry
// (internal/services/access/factory.go). Binaries blank-import THIS package so
// adding a connector is a one-line change here — no per-binary import list to
// keep in sync.
//
// Session 1A ships this as the empty aggregator. Session 1B adds the 200
// connector packages and a blank import for each below, plus a registry-count
// test that asserts the expected total.
package all

// Connector imports are added by Session 1B, one per provider, e.g.:
//
//	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/microsoft"
//	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/google_workspace"
//	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/okta"
