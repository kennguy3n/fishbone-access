package manual_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/connectors/manual"
)

func TestValidate(t *testing.T) {
	c := manual.New()
	ctx := context.Background()

	t.Run("empty config and secrets is valid", func(t *testing.T) {
		if err := c.Validate(ctx, nil, nil); err != nil {
			t.Fatalf("Validate(nil,nil) = %v; want nil", err)
		}
	})

	t.Run("descriptor config is valid", func(t *testing.T) {
		cfg := map[string]interface{}{"system_name": "Legacy payroll", "resource_kind": "application-role"}
		if err := c.Validate(ctx, cfg, nil); err != nil {
			t.Fatalf("Validate(cfg,nil) = %v; want nil", err)
		}
	})

	t.Run("non-string config field is rejected as validation error", func(t *testing.T) {
		cfg := map[string]interface{}{"system_name": 42}
		err := c.Validate(ctx, cfg, nil)
		if !errors.Is(err, access.ErrValidation) {
			t.Fatalf("Validate(bad cfg) = %v; want ErrValidation", err)
		}
	})

	t.Run("secrets are rejected — a manual target stores none", func(t *testing.T) {
		err := c.Validate(ctx, nil, map[string]interface{}{"token": "x"})
		if !errors.Is(err, access.ErrValidation) {
			t.Fatalf("Validate(secrets) = %v; want ErrValidation", err)
		}
	})
}

func TestProvisionRevokeIdempotentLocalSuccess(t *testing.T) {
	c := manual.New()
	ctx := context.Background()
	grant := access.AccessGrant{UserExternalID: "u@acme.test", ResourceExternalID: "payroll", Role: "operator"}

	for i := 0; i < 2; i++ { // idempotent: repeated calls both succeed
		if err := c.ProvisionAccess(ctx, nil, nil, grant); err != nil {
			t.Fatalf("ProvisionAccess attempt %d = %v; want nil", i, err)
		}
		if err := c.RevokeAccess(ctx, nil, nil, grant); err != nil {
			t.Fatalf("RevokeAccess attempt %d = %v; want nil", i, err)
		}
	}
}

func TestProvisionRejectsMalformedGrant(t *testing.T) {
	c := manual.New()
	ctx := context.Background()
	cases := map[string]access.AccessGrant{
		"missing user":     {ResourceExternalID: "payroll"},
		"missing resource": {UserExternalID: "u@acme.test"},
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			if err := c.ProvisionAccess(ctx, nil, nil, g); !errors.Is(err, access.ErrValidation) {
				t.Fatalf("ProvisionAccess(%s) = %v; want ErrValidation", name, err)
			}
		})
	}
}

func TestSyncIdentitiesEmptyNonNilBatchTerminates(t *testing.T) {
	c := manual.New()
	calls := 0
	err := c.SyncIdentities(context.Background(), nil, nil, "", func(batch []*access.Identity, next string) error {
		calls++
		if batch == nil {
			t.Errorf("batch is nil; contract requires a non-nil empty slice")
		}
		if len(batch) != 0 {
			t.Errorf("batch len = %d; want 0", len(batch))
		}
		if next != "" {
			t.Errorf("next checkpoint = %q; want terminal empty cursor", next)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("SyncIdentities = %v; want nil", err)
	}
	if calls != 1 {
		t.Fatalf("handler invoked %d times; want exactly 1", calls)
	}
}

func TestSSOAndEntitlementsAreEmpty(t *testing.T) {
	c := manual.New()
	ctx := context.Background()

	md, err := c.GetSSOMetadata(ctx, nil, nil)
	if err != nil || md != nil {
		t.Fatalf("GetSSOMetadata = (%v, %v); want (nil, nil)", md, err)
	}

	ents, err := c.ListEntitlements(ctx, nil, nil, "u@acme.test")
	if err != nil {
		t.Fatalf("ListEntitlements err = %v; want nil", err)
	}
	if ents == nil || len(ents) != 0 {
		t.Fatalf("ListEntitlements = %v; want non-nil empty slice", ents)
	}
}

func TestRegisteredInGlobalRegistry(t *testing.T) {
	got, err := access.GetAccessConnector(manual.ProviderName)
	if err != nil || got == nil {
		t.Fatalf("GetAccessConnector(%q) = (%v, %v); want a registered connector", manual.ProviderName, got, err)
	}
}
