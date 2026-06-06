package access

import (
	"fmt"
	"sort"
	"sync"
)

// Process-global access-connector registry. Connector packages register
// themselves from init() via RegisterAccessConnector; the running binary
// blank-imports connectors/all so every init() fires. Duplicate registration
// panics during init so a wiring bug (two connectors claiming one key) fails
// loudly instead of silently letting one win.
var (
	registry   = make(map[string]AccessConnector)
	registryMu sync.RWMutex
)

// RegisterAccessConnector registers connector under the lowercased snake_case
// provider key ("microsoft", "google_workspace", "okta", "generic_oidc", ...).
// Re-registration of an existing key panics; tests must use SwapConnector.
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

// GetAccessConnector returns the connector registered for provider, or
// ErrConnectorNotFound when no init() wired it (usually a missing blank-import).
func GetAccessConnector(provider string) (AccessConnector, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	connector, ok := registry[provider]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrConnectorNotFound, provider)
	}
	return connector, nil
}

// ListRegisteredProviders returns the sorted list of registered provider keys,
// for diagnostics and the connector-count CI guard.
func ListRegisteredProviders() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RegisteredCount returns the number of registered connectors. The connector
// count test (added in Session 1B) asserts this equals the expected total.
func RegisteredCount() int {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return len(registry)
}
