// These tests live in the access_test package so they can blank-import every
// connector to populate the process-global registry, then run each curated
// setup schema through the live connector's Validate — proving the schema's
// field keys and config/secret split match the connector contract it claims
// to document.
package access_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"

	// Blank-import the aggregate connector package so every provider is
	// registered before the assertions run.
	_ "github.com/kennguy3n/fishbone-access/internal/services/access/connectors/all"
)

// knownFieldTypes is the set of input controls the guided form can render. A
// schema field with any other type is a bug (the UI would not know how to
// render it).
var knownFieldTypes = map[access.SetupFieldType]bool{
	access.SetupFieldText:     true,
	access.SetupFieldPassword: true,
	access.SetupFieldTextarea: true,
	access.SetupFieldURL:      true,
	access.SetupFieldEmail:    true,
}

// TestSetupSchemaStructure asserts every curated schema is internally
// well-formed and consistent with the live catalogue: it documents a
// registered provider, its display name is registry-sourced, every auth method
// has at least one field and one required field, field keys are unique within a
// method, every field type is renderable, and at most one method is marked
// recommended.
func TestSetupSchemaStructure(t *testing.T) {
	for _, provider := range access.ProvidersWithSetupSchema() {
		provider := provider
		t.Run(provider, func(t *testing.T) {
			schema, ok := access.SetupSchemaFor(provider)
			if !ok {
				t.Fatalf("ProvidersWithSetupSchema listed %q but SetupSchemaFor returned false", provider)
			}
			if schema.Provider != provider {
				t.Errorf("schema.Provider = %q, want %q", schema.Provider, provider)
			}

			// The provider must be a registered connector with a curated
			// descriptor, and the schema's display name must come from it.
			desc, ok := access.CapabilityDescriptorFor(provider)
			if !ok {
				t.Fatalf("provider %q has a setup schema but no capability descriptor", provider)
			}
			if !desc.Registered {
				t.Errorf("provider %q has a setup schema but is not registered in the binary", provider)
			}
			if schema.DisplayName != desc.DisplayName {
				t.Errorf("schema.DisplayName = %q, want registry value %q", schema.DisplayName, desc.DisplayName)
			}

			if len(schema.AuthMethods) == 0 {
				t.Fatalf("provider %q has no auth methods", provider)
			}

			recommended := 0
			methodIDs := map[string]bool{}
			for _, m := range schema.AuthMethods {
				if m.ID == "" {
					t.Errorf("auth method has empty ID")
				}
				if methodIDs[m.ID] {
					t.Errorf("duplicate auth method ID %q", m.ID)
				}
				methodIDs[m.ID] = true
				if m.Label == "" {
					t.Errorf("auth method %q has empty label", m.ID)
				}
				if m.Recommended {
					recommended++
				}
				if len(m.Fields) == 0 {
					t.Errorf("auth method %q has no fields", m.ID)
				}

				fieldKeys := map[string]bool{}
				requiredCount := 0
				for _, f := range m.Fields {
					if f.Key == "" {
						t.Errorf("auth method %q has a field with empty key", m.ID)
					}
					if fieldKeys[f.Key] {
						t.Errorf("auth method %q has duplicate field key %q", m.ID, f.Key)
					}
					fieldKeys[f.Key] = true
					if f.Label == "" {
						t.Errorf("auth method %q field %q has empty label", m.ID, f.Key)
					}
					if f.Type != "" && !knownFieldTypes[f.Type] {
						t.Errorf("auth method %q field %q has unknown type %q", m.ID, f.Key, f.Type)
					}
					if f.Required {
						requiredCount++
					}
				}
				if requiredCount == 0 {
					t.Errorf("auth method %q has no required fields", m.ID)
				}
			}
			if recommended > 1 {
				t.Errorf("provider %q marks %d auth methods recommended, want at most 1", provider, recommended)
			}
		})
	}
}

// sampleValues are valid-for-Validate example values per provider, keyed by the
// schema field key. They let the round-trip test build a payload the live
// connector accepts, which is what proves the schema keys + secret split match
// the connector contract. Values satisfy each connector's offline validate
// (format/JSON/UUID checks), not real credentials.
var sampleValues = map[string]map[string]string{
	"okta": {
		"okta_domain": "dev-12345.okta.com",
		"api_token":   "SSWS 00abcdefghijklmnop",
	},
	"microsoft": {
		"tenant_id":     "11111111-1111-1111-1111-111111111111",
		"client_id":     "22222222-2222-2222-2222-222222222222",
		"client_secret": "entra-client-secret-value",
	},
	"google_workspace": {
		"domain":              "example.com",
		"admin_email":         "admin@example.com",
		"service_account_key": sampleGoogleServiceAccountKey,
	},
	"auth0": {
		"domain":        "tenant.us.auth0.com",
		"client_id":     "auth0-m2m-client-id",
		"client_secret": "auth0-m2m-client-secret",
	},
	"aws": {
		"aws_region":            "us-east-1",
		"aws_account_id":        "123456789012",
		"aws_access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	},
	"azure": {
		"tenant_id":       "33333333-3333-3333-3333-333333333333",
		"subscription_id": "44444444-4444-4444-4444-444444444444",
		"client_id":       "55555555-5555-5555-5555-555555555555",
		"client_secret":   "azure-sp-client-secret",
	},
	"gcp": {
		"project_id":           "my-project-123456",
		"service_account_json": sampleGCPServiceAccountJSON,
		"customer_id":          "C01abcdef",
	},
	"github": {
		"organization": "example-org",
		"access_token": "ghp_exampletokenvalue0000000000000000",
	},
	"cloudflare": {
		"account_id":  "0123456789abcdef0123456789abcdef",
		"email":       "you@example.com",
		"team_domain": "acme",
		"api_token":   "cf-scoped-api-token-value",
		"api_key":     "cf-global-api-key-value",
	},
}

const sampleGoogleServiceAccountKey = `{
  "type": "service_account",
  "project_id": "example-123456",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEexample\n-----END PRIVATE KEY-----\n",
  "client_email": "sa@example-123456.iam.gserviceaccount.com",
  "client_id": "1234567890"
}`

const sampleGCPServiceAccountJSON = `{
  "type": "service_account",
  "project_id": "my-project-123456",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEexample\n-----END PRIVATE KEY-----\n",
  "client_email": "sa@my-project-123456.iam.gserviceaccount.com",
  "client_id": "1234567890"
}`

// TestSetupSchemaMatchesConnectorContract is the anti-drift guard: for every
// curated schema, and every auth method in it, building a payload from the
// schema's required fields (routed into config/secrets by the Secret flag) must
// pass the live connector's Validate. A schema field key that the connector
// does not read, or one placed in the wrong bucket, would leave a required
// value unset and Validate would reject it — failing this test.
func TestSetupSchemaMatchesConnectorContract(t *testing.T) {
	ctx := context.Background()
	for _, provider := range access.ProvidersWithSetupSchema() {
		provider := provider
		schema, _ := access.SetupSchemaFor(provider)
		samples, ok := sampleValues[provider]
		if !ok {
			t.Errorf("provider %q has a setup schema but no test sample values; add them so the schema is verified against the connector", provider)
			continue
		}
		connector, err := access.GetAccessConnector(provider)
		if err != nil {
			t.Errorf("GetAccessConnector(%q): %v", provider, err)
			continue
		}
		for _, m := range schema.AuthMethods {
			t.Run(provider+"/"+m.ID, func(t *testing.T) {
				config := map[string]interface{}{}
				secrets := map[string]interface{}{}
				for _, f := range m.Fields {
					if !f.Required {
						continue
					}
					val, ok := samples[f.Key]
					if !ok {
						t.Fatalf("missing sample value for required field %q", f.Key)
					}
					if f.Secret {
						secrets[f.Key] = val
					} else {
						config[f.Key] = val
					}
				}
				if err := connector.Validate(ctx, config, secrets); err != nil {
					t.Errorf("Validate rejected a payload built from the schema's required fields: %v\nconfig keys=%v secret keys=%v", err, keysOf(config), keysOf(secrets))
				}
			})
		}
	}
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
