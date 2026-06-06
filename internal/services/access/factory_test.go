package access

import (
	"errors"
	"testing"
)

// withCleanRegistrySlot wipes the registry entry for provider for the duration
// of the test and restores anything that was there before. Used by tests that
// need to assert behaviour against an empty slot (e.g. duplicate-register
// panics, missing-key lookups).
func withCleanRegistrySlot(t *testing.T, provider string) {
	t.Helper()

	registryMu.Lock()
	previous, hadPrevious := registry[provider]
	delete(registry, provider)
	registryMu.Unlock()

	t.Cleanup(func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		if hadPrevious {
			registry[provider] = previous
		} else {
			delete(registry, provider)
		}
	})
}

func TestRegisterAccessConnector_AndGet(t *testing.T) {
	const provider = "test_register_get"
	withCleanRegistrySlot(t, provider)

	mock := &MockAccessConnector{}
	RegisterAccessConnector(provider, mock)

	got, err := GetAccessConnector(provider)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q) returned error: %v", provider, err)
	}
	if got != mock {
		t.Fatalf("GetAccessConnector(%q) returned different instance", provider)
	}
}

func TestGetAccessConnector_UnknownProvider(t *testing.T) {
	const provider = "test_unknown_provider_xyz"
	withCleanRegistrySlot(t, provider)

	_, err := GetAccessConnector(provider)
	if err == nil {
		t.Fatalf("GetAccessConnector(%q) returned nil error for unknown provider", provider)
	}
	if !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("GetAccessConnector(%q) error = %v, want errors.Is ErrConnectorNotFound", provider, err)
	}
}

func TestRegisterAccessConnector_DuplicatePanics(t *testing.T) {
	const provider = "test_duplicate_register"
	withCleanRegistrySlot(t, provider)

	RegisterAccessConnector(provider, &MockAccessConnector{})

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on duplicate RegisterAccessConnector(%q), got none", provider)
		}
	}()

	RegisterAccessConnector(provider, &MockAccessConnector{})
}

func TestRegisterAccessConnector_EmptyProviderPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on RegisterAccessConnector with empty provider, got none")
		}
	}()
	RegisterAccessConnector("", &MockAccessConnector{})
}

func TestRegisterAccessConnector_NilConnectorPanics(t *testing.T) {
	const provider = "test_nil_connector"
	withCleanRegistrySlot(t, provider)

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on RegisterAccessConnector with nil connector, got none")
		}
	}()
	RegisterAccessConnector(provider, nil)
}

func TestSwapConnector_RestoresOnCleanup(t *testing.T) {
	const provider = "test_swap_restore"
	withCleanRegistrySlot(t, provider)

	original := &MockAccessConnector{}
	RegisterAccessConnector(provider, original)

	t.Run("swap subtest", func(t *testing.T) {
		mock := &MockAccessConnector{}
		SwapConnector(t, provider, mock)

		got, err := GetAccessConnector(provider)
		if err != nil {
			t.Fatalf("GetAccessConnector(%q) inside swap: %v", provider, err)
		}
		if got != mock {
			t.Fatalf("GetAccessConnector(%q) inside swap returned wrong instance", provider)
		}
	})

	got, err := GetAccessConnector(provider)
	if err != nil {
		t.Fatalf("GetAccessConnector(%q) after subtest: %v", provider, err)
	}
	if got != original {
		t.Fatalf("SwapConnector did not restore original; got %v, want %v", got, original)
	}
}

func TestSwapConnector_RestoresAbsenceOnCleanup(t *testing.T) {
	const provider = "test_swap_no_previous"
	withCleanRegistrySlot(t, provider)

	t.Run("swap into empty slot", func(t *testing.T) {
		mock := &MockAccessConnector{}
		SwapConnector(t, provider, mock)

		got, err := GetAccessConnector(provider)
		if err != nil {
			t.Fatalf("GetAccessConnector(%q) inside swap: %v", provider, err)
		}
		if got != mock {
			t.Fatalf("GetAccessConnector(%q) inside swap returned wrong instance", provider)
		}
	})

	if _, err := GetAccessConnector(provider); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("expected ErrConnectorNotFound after swap cleanup, got %v", err)
	}
}

func TestListRegisteredProviders_IncludesRegistered(t *testing.T) {
	const provider = "test_list_provider"
	withCleanRegistrySlot(t, provider)

	RegisterAccessConnector(provider, &MockAccessConnector{})

	providers := ListRegisteredProviders()
	found := false
	for _, p := range providers {
		if p == provider {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListRegisteredProviders() = %v, expected to contain %q", providers, provider)
	}
}
