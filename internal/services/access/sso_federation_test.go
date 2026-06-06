package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

// fakeConnections is an in-memory ConnectionConfigurator capturing the last
// created connection for assertions.
type fakeConnections struct {
	created   *iamcore.Connection
	createErr error
	deletedID string
}

func (f *fakeConnections) CreateConnection(_ context.Context, conn iamcore.Connection) (*iamcore.Connection, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	conn.ID = "conn-123"
	f.created = &conn
	return &conn, nil
}
func (f *fakeConnections) DeleteConnection(_ context.Context, id string) error {
	f.deletedID = id
	return nil
}
func (f *fakeConnections) TestConnection(context.Context, string) error         { return nil }
func (f *fakeConnections) ToggleConnection(context.Context, string, bool) error { return nil }

func ssoMock(meta *SSOMetadata, err error) *MockAccessConnector {
	return &MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
			return meta, err
		},
	}
}

func TestConfigureSSOMicrosoftStrategy(t *testing.T) {
	fake := &fakeConnections{}
	svc := NewSSOFederationService(fake)
	ws := uuid.New()
	conn := ssoMock(&SSOMetadata{Protocol: "oidc", MetadataURL: "https://login.microsoftonline.com/x/.well-known/openid-configuration", EntityID: "entra-tenant"}, nil)

	out, err := svc.ConfigureSSO(context.Background(), ConfigureSSOInput{
		WorkspaceID: ws,
		Provider:    "microsoft",
		Connector:   conn,
		Secrets:     map[string]interface{}{"sso_client_id": "cid", "sso_client_secret": "sec"},
	})
	if err != nil {
		t.Fatalf("ConfigureSSO: %v", err)
	}
	if out.Strategy != "microsoft" {
		t.Errorf("strategy = %q, want microsoft", out.Strategy)
	}
	if fake.created.Options["discovery_url"] == "" {
		t.Error("discovery_url not set in options")
	}
	if fake.created.Options["client_id"] != "cid" {
		t.Errorf("client_id = %v, want cid", fake.created.Options["client_id"])
	}
	wantName := "shieldnet-microsoft-" + ws.String()
	if out.Name != wantName {
		t.Errorf("name = %q, want %q", out.Name, wantName)
	}
}

func TestConfigureSSOStrategyMapping(t *testing.T) {
	cases := map[string]string{
		"google_workspace": "google-oauth2",
		"okta":             "oidc",
		"auth0":            "oidc",
		"ping_identity":    "oidc",
		"github":           "github",
		"zoho_crm":         "zoho",
	}
	for provider, wantStrategy := range cases {
		t.Run(provider, func(t *testing.T) {
			fake := &fakeConnections{}
			svc := NewSSOFederationService(fake)
			conn := ssoMock(&SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp/.well-known/openid-configuration"}, nil)
			out, err := svc.ConfigureSSO(context.Background(), ConfigureSSOInput{
				WorkspaceID: uuid.New(),
				Provider:    provider,
				Connector:   conn,
			})
			if err != nil {
				t.Fatalf("ConfigureSSO: %v", err)
			}
			if out.Strategy != wantStrategy {
				t.Errorf("provider %q strategy = %q, want %q", provider, out.Strategy, wantStrategy)
			}
		})
	}
}

func TestConfigureSSOGenericProtocolFallback(t *testing.T) {
	fake := &fakeConnections{}
	svc := NewSSOFederationService(fake)
	// Unknown provider, SAML metadata → generic saml slug.
	conn := ssoMock(&SSOMetadata{Protocol: "saml", MetadataURL: "https://idp/saml/metadata", SigningCertificates: []string{"PEMDATA"}}, nil)
	out, err := svc.ConfigureSSO(context.Background(), ConfigureSSOInput{
		WorkspaceID: uuid.New(),
		Provider:    "some_saml_idp",
		Connector:   conn,
	})
	if err != nil {
		t.Fatalf("ConfigureSSO: %v", err)
	}
	if out.Strategy != "saml" {
		t.Errorf("strategy = %q, want saml", out.Strategy)
	}
	if fake.created.Options["signing_certificates"] == nil {
		t.Error("signing_certificates not propagated")
	}
}

func TestConfigureSSOUnknownStrategy(t *testing.T) {
	svc := NewSSOFederationService(&fakeConnections{})
	conn := ssoMock(&SSOMetadata{Protocol: "carrier-pigeon"}, nil)
	_, err := svc.ConfigureSSO(context.Background(), ConfigureSSOInput{
		WorkspaceID: uuid.New(),
		Provider:    "weird",
		Connector:   conn,
	})
	if !errors.Is(err, ErrSSOStrategyUnknown) {
		t.Errorf("err = %v, want ErrSSOStrategyUnknown", err)
	}
}

func TestConfigureSSOUnsupported(t *testing.T) {
	svc := NewSSOFederationService(&fakeConnections{})
	// Connector advertises no SSO metadata.
	conn := ssoMock(nil, nil)
	_, err := svc.ConfigureSSO(context.Background(), ConfigureSSOInput{
		WorkspaceID: uuid.New(),
		Provider:    "okta",
		Connector:   conn,
	})
	if !errors.Is(err, ErrSSOFederationUnsupported) {
		t.Errorf("err = %v, want ErrSSOFederationUnsupported", err)
	}
}

func TestConfigureSSODisabled(t *testing.T) {
	svc := NewSSOFederationService(nil)
	_, err := svc.ConfigureSSO(context.Background(), ConfigureSSOInput{
		WorkspaceID: uuid.New(),
		Provider:    "okta",
		Connector:   ssoMock(&SSOMetadata{Protocol: "oidc"}, nil),
	})
	if !errors.Is(err, ErrSSOFederationDisabled) {
		t.Errorf("err = %v, want ErrSSOFederationDisabled", err)
	}
}

func TestRemoveSSO(t *testing.T) {
	fake := &fakeConnections{}
	svc := NewSSOFederationService(fake)
	if err := svc.RemoveSSO(context.Background(), "conn-123"); err != nil {
		t.Fatalf("RemoveSSO: %v", err)
	}
	if fake.deletedID != "conn-123" {
		t.Errorf("deleted id = %q, want conn-123", fake.deletedID)
	}
}

// TestConfigureSSOThroughRealClient exercises the full path through the real
// iamcore.ManagementClient against a mock iam-core (httptest), verifying the
// client_credentials mint + connection POST serialization.
func TestConfigureSSOThroughRealClient(t *testing.T) {
	var gotBody iamcore.Connection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600, "token_type": "Bearer"})
		case "/api/v1/management/connections":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			resp := gotBody
			resp.ID = "conn-real"
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := iamcore.NewManagementClient(config.IAMCoreConfig{
		Issuer:       srv.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		Audience:     "mgmt",
	}, srv.Client())

	svc := NewSSOFederationService(client)
	conn := ssoMock(&SSOMetadata{Protocol: "oidc", MetadataURL: srv.URL + "/.well-known/openid-configuration"}, nil)
	out, err := svc.ConfigureSSO(context.Background(), ConfigureSSOInput{
		WorkspaceID: uuid.New(),
		Provider:    "okta",
		Connector:   conn,
	})
	if err != nil {
		t.Fatalf("ConfigureSSO: %v", err)
	}
	if out.ID != "conn-real" {
		t.Errorf("connection id = %q, want conn-real", out.ID)
	}
	if gotBody.Strategy != "oidc" {
		t.Errorf("posted strategy = %q, want oidc", gotBody.Strategy)
	}
}
