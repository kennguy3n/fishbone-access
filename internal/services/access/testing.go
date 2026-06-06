package access

import "testing"

// SwapConnector temporarily registers (or replaces) the connector for provider
// for the duration of a test, restoring the previous state via t.Cleanup. Tests
// use this instead of calling RegisterAccessConnector directly, which would
// panic on the duplicate-registration guard.
func SwapConnector(t *testing.T, provider string, connector AccessConnector) {
	t.Helper()
	registryMu.Lock()
	prev, had := registry[provider]
	registry[provider] = connector
	registryMu.Unlock()

	t.Cleanup(func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		if had {
			registry[provider] = prev
		} else {
			delete(registry, provider)
		}
	})
}
