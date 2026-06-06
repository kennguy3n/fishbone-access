package access

import (
	"fmt"
	"sort"
	"sync"
)

// Process-global access connector registry. Mirrors the SN360 connector
// pattern from shieldnet360-backend/internal/services/connectors/factory.go:9-32
// but with one defensive change: duplicate registration panics during init
// instead of silently overwriting, so init-time wiring bugs (two connectors
// claiming the same provider key) fail loudly.
//
// Tests legitimately swap registry entries; use SwapConnector from testing.go
// which restores the previous instance via t.Cleanup.
var (
	registry   = make(map[string]AccessConnector)
	registryMu sync.RWMutex
)

// RegisterAccessConnector registers a connector instance for the given
// provider key. Provider keys are lowercased, snake_case (per
// docs/architecture.md §3): "microsoft", "google_workspace", "okta",
// "generic_saml", ...
//
// Re-registration of an already-registered key panics. Two connectors
// claiming the same key is always a wiring bug — silently letting one win
// would mask it until production. Tests must use SwapConnector instead of
// calling RegisterAccessConnector twice.
func RegisterAccessConnector(provider string, connector AccessConnector) {
	if provider == "" {
		panic("access: RegisterAccessConnector called with empty provider key")
	}
	if connector == nil {
		panic(fmt.Sprintf("access: RegisterAccessConnector(%q) called with nil connector", provider))
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[provider]; exists {
		panic(fmt.Sprintf("access: connector for provider %q already registered", provider))
	}
	registry[provider] = connector
}

// GetAccessConnector returns the connector registered for the given provider
// key, or ErrConnectorNotFound if no init() side-effect has wired it. The
// most common cause of ErrConnectorNotFound in production is a binary that
// forgot the blank-import for a connector package.
func GetAccessConnector(provider string) (AccessConnector, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	connector, ok := registry[provider]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrConnectorNotFound, provider)
	}
	return connector, nil
}

// ListRegisteredProviders returns the sorted list of provider keys currently
// in the registry. Intended for diagnostics endpoints and debug logging only —
// not the source of truth for the provider catalogue (that lives in
// docs/connectors.md §1).
func ListRegisteredProviders() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	out := make([]string, 0, len(registry))
	for provider := range registry {
		out = append(out, provider)
	}
	sort.Strings(out)
	return out
}

// RegisteredCount returns the number of connectors currently registered. The
// connector-count guard (registry_count_test.go) asserts this equals the
// expected total; the ztna-api /api/v1 diagnostics surface also reports it.
func RegisteredCount() int {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return len(registry)
}
