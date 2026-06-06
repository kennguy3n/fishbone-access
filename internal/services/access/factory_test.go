package access

import (
	"context"
	"errors"
	"testing"
)

// noopConnector is a minimal AccessConnector used to exercise the registry.
type noopConnector struct{}

func (noopConnector) Validate(context.Context, map[string]any, map[string]any) error {
	return nil
}
func (noopConnector) Connect(context.Context, map[string]any, map[string]any) error { return nil }
func (noopConnector) VerifyPermissions(context.Context, map[string]any, map[string]any, []string) ([]string, error) {
	return nil, nil
}
func (noopConnector) CountIdentities(context.Context, map[string]any, map[string]any) (int, error) {
	return 0, nil
}
func (noopConnector) SyncIdentities(context.Context, map[string]any, map[string]any, string, func([]*Identity, string) error) error {
	return nil
}
func (noopConnector) ProvisionAccess(context.Context, map[string]any, map[string]any, AccessGrant) error {
	return nil
}
func (noopConnector) RevokeAccess(context.Context, map[string]any, map[string]any, AccessGrant) error {
	return nil
}
func (noopConnector) ListEntitlements(context.Context, map[string]any, map[string]any, string) ([]Entitlement, error) {
	return nil, nil
}
func (noopConnector) GetSSOMetadata(context.Context, map[string]any, map[string]any) (*SSOMetadata, error) {
	return nil, nil
}
func (noopConnector) GetCredentialsMetadata(context.Context, map[string]any, map[string]any) (*CredentialsMetadata, error) {
	return nil, nil
}

func TestRegisterAndGet(t *testing.T) {
	SwapConnector(t, "test_provider", noopConnector{})
	got, err := GetAccessConnector("test_provider")
	if err != nil {
		t.Fatalf("GetAccessConnector: %v", err)
	}
	if got == nil {
		t.Fatal("got nil connector")
	}
}

func TestGetUnknownProvider(t *testing.T) {
	if _, err := GetAccessConnector("does_not_exist"); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("err = %v, want ErrConnectorNotFound", err)
	}
}

func TestListRegisteredProvidersSorted(t *testing.T) {
	SwapConnector(t, "zeta", noopConnector{})
	SwapConnector(t, "alpha", noopConnector{})
	list := ListRegisteredProviders()
	var ai, zi = -1, -1
	for i, p := range list {
		switch p {
		case "alpha":
			ai = i
		case "zeta":
			zi = i
		}
	}
	if ai == -1 || zi == -1 || ai > zi {
		t.Fatalf("providers not sorted as expected: %v", list)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	// Seed the key via SwapConnector so the registration is cleaned up after
	// the test (t.Cleanup) and does not permanently pollute the process-global
	// registry — the second call still hits the real duplicate-guard panic.
	SwapConnector(t, "dup", noopConnector{})
	RegisterAccessConnector("dup", noopConnector{})
}
