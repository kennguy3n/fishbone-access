package access

import "sort"

// Connector setup schemas make a provider's connection form self-describing.
//
// The capability matrix answers "what can this connector do?"; the AI setup
// assistant answers "how, in prose, do I approach this?". Neither answers the
// concrete, low-skill-operator question this file targets: "which exact fields
// must I fill in, what kind of value does each take, and where in the upstream
// console do I find it?". Without that, the connect form is a raw key/value
// editor and the operator has to already know that Okta wants an okta_domain +
// an SSWS api_token, that Entra wants two UUIDs + a client secret, and so on.
//
// A ConnectorSetupSchema is curated, deterministic metadata (never AI, never a
// network call) that the connect UI renders into a typed, labelled form with
// inline "where do I find this?" help. The field keys MUST match the keys the
// connector's DecodeConfig/DecodeSecrets read and the Secret flag MUST match
// which map (config vs secrets) the connector decodes that key from — the
// schema describes the existing connector contract, it does not redefine it.
// connector_setup_schema_test.go pins both invariants by building a sample
// payload from each schema and running it through the live connector's
// Validate, so a schema can never drift from the connector it documents.

// SetupFieldType is the input control the guided connect form renders for a
// field. It is advisory rendering metadata only; the server-side connector
// Validate remains authoritative for what a value must actually be.
type SetupFieldType string

const (
	// SetupFieldText is a single-line free-text input.
	SetupFieldText SetupFieldType = "text"
	// SetupFieldPassword is a single-line input whose value is masked in the
	// UI (used for tokens, secrets, and keys that are short enough to type on
	// one line).
	SetupFieldPassword SetupFieldType = "password"
	// SetupFieldTextarea is a multi-line input, used for pasted credentials
	// that span many lines (e.g. a service-account JSON key).
	SetupFieldTextarea SetupFieldType = "textarea"
	// SetupFieldURL is a single-line input expecting a URL.
	SetupFieldURL SetupFieldType = "url"
	// SetupFieldEmail is a single-line input expecting an email address.
	SetupFieldEmail SetupFieldType = "email"
)

// SetupField describes one input in a provider's connect form.
type SetupField struct {
	// Key is the exact config/secret key the connector decodes. It is sent to
	// POST /connectors under "config" when Secret is false and under "secrets"
	// when Secret is true.
	Key string `json:"key"`
	// Label is the human field name shown above the input.
	Label string `json:"label"`
	// Type selects the input control. Empty defaults to a text input.
	Type SetupFieldType `json:"type"`
	// Secret routes the value into the secrets bucket (sealed under the
	// workspace key, never returned) rather than config. It MUST match the map
	// the connector reads this key from.
	Secret bool `json:"secret"`
	// Required marks a field the connector rejects when blank. The form blocks
	// submission until every required field of the chosen method is filled.
	Required bool `json:"required"`
	// Placeholder is an example value shown in the empty input.
	Placeholder string `json:"placeholder,omitempty"`
	// Help is the plain-language "where do I find this / what is it?" hint
	// shown under the field — the core of the guided experience.
	Help string `json:"help,omitempty"`
	// Pattern is an optional JavaScript-compatible regex the UI may use for
	// inline format hints. It is advisory only and intentionally lenient; the
	// connector Validate is the authority.
	Pattern string `json:"pattern,omitempty"`
}

// SetupAuthMethod is one way to authenticate a connector. Most providers have
// a single method; some (e.g. Cloudflare) offer a preferred token method and a
// legacy fallback, so the form lets the operator pick.
type SetupAuthMethod struct {
	// ID is a stable key for the method (e.g. "api_token").
	ID string `json:"id"`
	// Label is the human method name shown in the picker.
	Label string `json:"label"`
	// Description is a one-line explanation of the method.
	Description string `json:"description,omitempty"`
	// DocsURL deep-links the provider's own documentation for obtaining these
	// credentials.
	DocsURL string `json:"docs_url,omitempty"`
	// Recommended marks the method the operator should prefer when more than
	// one is offered. At most one method per schema is recommended.
	Recommended bool `json:"recommended,omitempty"`
	// Steps is an ordered, plain-language "how to get these credentials"
	// checklist rendered above the fields.
	Steps []string `json:"steps,omitempty"`
	// Fields are the inputs to collect for this method, in display order.
	Fields []SetupField `json:"fields"`
}

// ConnectorSetupSchema is the complete guided-setup descriptor for one
// provider. Provider and DisplayName are filled from the live registry at
// lookup time (see SetupSchemaFor) so they can never drift from the catalogue.
type ConnectorSetupSchema struct {
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
	// Overview is a short, provider-level orientation sentence shown once at
	// the top of the form, above the auth-method picker.
	Overview string `json:"overview,omitempty"`
	// DocsURL is the provider's top-level connector documentation.
	DocsURL     string            `json:"docs_url,omitempty"`
	AuthMethods []SetupAuthMethod `json:"auth_methods"`
}

const (
	uuidPattern      = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	awsRegionPattern = `^[a-z]{2}(-[a-z]+)+-\d$`
)

// connectorSetupSchemas is the curated guided-setup metadata, keyed by the
// exact registry provider key. Entries omit Provider/DisplayName — those are
// resolved from the registry by SetupSchemaFor. Not every provider has an
// entry yet; the connect form falls back to the manual key/value editor for
// providers without a curated schema, so coverage can grow incrementally
// without breaking any connector.
var connectorSetupSchemas = map[string]ConnectorSetupSchema{
	"okta": {
		Overview: "Connect your Okta org with a read/manage API token so the platform can sync users and groups and enforce access.",
		DocsURL:  "https://developer.okta.com/docs/guides/create-an-api-token/main/",
		AuthMethods: []SetupAuthMethod{{
			ID:          "api_token",
			Label:       "API token",
			Description: "A standard Okta API token (SSWS) scoped to an admin who can read users and groups.",
			DocsURL:     "https://developer.okta.com/docs/guides/create-an-api-token/main/",
			Recommended: true,
			Steps: []string{
				"Sign in to the Okta Admin Console as a Super Admin or a Read-Only Admin.",
				"Go to Security → API → Tokens, then click Create Token.",
				"Name it (e.g. \"ShieldNet sync\"), create it, and copy the token value — Okta shows it only once.",
				"Your Okta domain is the address you sign in at, e.g. dev-12345.okta.com.",
			},
			Fields: []SetupField{
				{Key: "okta_domain", Label: "Okta domain", Type: SetupFieldText, Required: true, Placeholder: "dev-12345.okta.com", Help: "The host you sign in to Okta at. Ends in .okta.com, .oktapreview.com, or .okta-emea.com. Paste without https://."},
				{Key: "api_token", Label: "API token", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "00aBcD…", Help: "The token value from Security → API → Tokens. You may paste it with or without the leading \"SSWS \"."},
			},
		}},
	},

	"microsoft": {
		Overview: "Connect Microsoft Entra ID (Azure AD) with an app registration. The platform uses the app's client credentials to read your directory.",
		DocsURL:  "https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app",
		AuthMethods: []SetupAuthMethod{{
			ID:          "app_registration",
			Label:       "App registration (client credentials)",
			Description: "An Entra app registration with a client secret and Microsoft Graph application permissions.",
			DocsURL:     "https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app",
			Recommended: true,
			Steps: []string{
				"In the Entra admin center, go to Identity → Applications → App registrations → New registration.",
				"On the app's Overview page, copy the Directory (tenant) ID and the Application (client) ID — both are UUIDs.",
				"Under Certificates & secrets → Client secrets, create a new secret and copy its Value (not the Secret ID).",
				"Under API permissions, grant the Microsoft Graph application permissions your sync needs (e.g. User.Read.All, Group.Read.All) and click Grant admin consent.",
			},
			Fields: []SetupField{
				{Key: "tenant_id", Label: "Directory (tenant) ID", Type: SetupFieldText, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000", Help: "The Directory (tenant) ID from your app registration's Overview page. A UUID.", Pattern: uuidPattern},
				{Key: "client_id", Label: "Application (client) ID", Type: SetupFieldText, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000", Help: "The Application (client) ID from the same Overview page. A UUID.", Pattern: uuidPattern},
				{Key: "client_secret", Label: "Client secret", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "the secret Value", Help: "The Value of the client secret you created under Certificates & secrets. Copy it immediately — Entra hides it after you leave the page."},
			},
		}},
	},

	"google_workspace": {
		Overview: "Connect Google Workspace with a service account that has domain-wide delegation, impersonating a super-admin to read your directory.",
		DocsURL:  "https://support.google.com/a/answer/7378726",
		AuthMethods: []SetupAuthMethod{{
			ID:          "service_account",
			Label:       "Service account (domain-wide delegation)",
			Description: "A Google Cloud service account JSON key with domain-wide delegation, impersonating an admin.",
			DocsURL:     "https://support.google.com/a/answer/7378726",
			Recommended: true,
			Steps: []string{
				"In the Google Cloud console, create a service account and create a JSON key for it — your browser downloads the key file.",
				"In the Admin console, go to Security → Access and data control → API controls → Domain-wide delegation and authorise the service account's client ID for the Admin SDK scopes.",
				"Open the downloaded JSON file in a text editor and paste its entire contents below.",
				"Admin email is a super-admin in your domain that the service account will impersonate.",
			},
			Fields: []SetupField{
				{Key: "domain", Label: "Workspace domain", Type: SetupFieldText, Required: true, Placeholder: "example.com", Help: "Your primary Google Workspace domain."},
				{Key: "admin_email", Label: "Admin email to impersonate", Type: SetupFieldEmail, Required: true, Placeholder: "admin@example.com", Help: "A super-admin account in your domain. The service account impersonates this user to read the directory."},
				{Key: "service_account_key", Label: "Service account JSON key", Type: SetupFieldTextarea, Secret: true, Required: true, Placeholder: `{ "type": "service_account", … }`, Help: "Paste the full contents of the service-account JSON key file you downloaded. It must be a service_account key (it includes client_email and private_key)."},
			},
		}},
	},

	"auth0": {
		Overview: "Connect Auth0 with a Machine-to-Machine application authorised against the Auth0 Management API.",
		DocsURL:  "https://auth0.com/docs/get-started/auth0-overview/create-applications/machine-to-machine-apps",
		AuthMethods: []SetupAuthMethod{{
			ID:          "m2m",
			Label:       "Machine-to-Machine application",
			Description: "An Auth0 M2M application authorised for the Auth0 Management API.",
			DocsURL:     "https://auth0.com/docs/get-started/auth0-overview/create-applications/machine-to-machine-apps",
			Recommended: true,
			Steps: []string{
				"In the Auth0 dashboard, go to Applications → Applications → Create Application and choose Machine to Machine.",
				"Authorise it for the Auth0 Management API and grant the read scopes you need (e.g. read:users, read:roles).",
				"On the application's Settings tab, copy the Domain, Client ID, and Client Secret.",
			},
			Fields: []SetupField{
				{Key: "domain", Label: "Auth0 domain", Type: SetupFieldText, Required: true, Placeholder: "your-tenant.us.auth0.com", Help: "Your Auth0 tenant domain from the application Settings. Contains .auth0.com."},
				{Key: "client_id", Label: "Client ID", Type: SetupFieldText, Secret: true, Required: true, Placeholder: "the M2M application Client ID", Help: "The Client ID of the Machine-to-Machine application."},
				{Key: "client_secret", Label: "Client secret", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "the M2M application Client Secret", Help: "The Client Secret from the same Settings tab."},
			},
		}},
	},

	"aws": {
		Overview: "Connect an AWS account with IAM access keys so the platform can read and manage IAM users and access.",
		DocsURL:  "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
		AuthMethods: []SetupAuthMethod{{
			ID:          "iam_access_key",
			Label:       "IAM access key",
			Description: "An IAM user's access key ID and secret access key, scoped to the IAM read/manage actions you need.",
			DocsURL:     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
			Recommended: true,
			Steps: []string{
				"In the AWS IAM console, create (or pick) an IAM user dedicated to this integration.",
				"Attach a policy granting the IAM read/manage actions you need (e.g. iam:ListUsers, iam:GetUser).",
				"Under the user's Security credentials, create an access key and copy both the Access key ID and the Secret access key.",
				"Your region is where you operate (e.g. us-east-1); the 12-digit account ID is optional but recommended.",
			},
			Fields: []SetupField{
				{Key: "aws_region", Label: "Region", Type: SetupFieldText, Required: true, Placeholder: "us-east-1", Help: "The AWS region to talk to, e.g. us-east-1 or eu-west-1.", Pattern: awsRegionPattern},
				{Key: "aws_account_id", Label: "Account ID", Type: SetupFieldText, Required: false, Placeholder: "123456789012", Help: "Optional. Your 12-digit AWS account ID, shown in the top-right of the console."},
				{Key: "aws_access_key_id", Label: "Access key ID", Type: SetupFieldText, Secret: true, Required: true, Placeholder: "AKIA…", Help: "The Access key ID of the IAM user's access key."},
				{Key: "aws_secret_access_key", Label: "Secret access key", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "the secret access key", Help: "The Secret access key shown only once when you created the access key."},
			},
		}},
	},

	"azure": {
		Overview: "Connect an Azure subscription with an app registration (service principal) that has RBAC read/manage on the subscription.",
		DocsURL:  "https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal",
		AuthMethods: []SetupAuthMethod{{
			ID:          "service_principal",
			Label:       "App registration (service principal)",
			Description: "An Entra app registration with a client secret, assigned an RBAC role on the target subscription.",
			DocsURL:     "https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal",
			Recommended: true,
			Steps: []string{
				"Create an Entra app registration and a client secret (same as for Microsoft Entra ID).",
				"In the Azure portal, open the target Subscription → Access control (IAM) and assign the app a role (e.g. Reader, or a custom role for role-assignment management).",
				"Copy the Directory (tenant) ID, the Application (client) ID, the client secret Value, and the Subscription ID.",
			},
			Fields: []SetupField{
				{Key: "tenant_id", Label: "Directory (tenant) ID", Type: SetupFieldText, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000", Help: "The Directory (tenant) ID of the app registration.", Pattern: uuidPattern},
				{Key: "subscription_id", Label: "Subscription ID", Type: SetupFieldText, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000", Help: "The ID of the Azure subscription whose RBAC you want to manage.", Pattern: uuidPattern},
				{Key: "client_id", Label: "Application (client) ID", Type: SetupFieldText, Secret: true, Required: true, Placeholder: "00000000-0000-0000-0000-000000000000", Help: "The Application (client) ID of the app registration.", Pattern: uuidPattern},
				{Key: "client_secret", Label: "Client secret", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "the secret Value", Help: "The Value of the app registration's client secret."},
			},
		}},
	},

	"gcp": {
		Overview: "Connect a Google Cloud project with a service account JSON key that has IAM read/manage on the project.",
		DocsURL:  "https://cloud.google.com/iam/docs/keys-create-delete",
		AuthMethods: []SetupAuthMethod{{
			ID:          "service_account",
			Label:       "Service account key",
			Description: "A Google Cloud service account JSON key with the IAM roles your sync and provisioning need.",
			DocsURL:     "https://cloud.google.com/iam/docs/keys-create-delete",
			Recommended: true,
			Steps: []string{
				"In the Google Cloud console, go to IAM & Admin → Service Accounts and create (or pick) a service account in the target project.",
				"Grant it the IAM roles you need (e.g. roles/iam.securityReviewer to read, roles/resourcemanager.projectIamAdmin to manage bindings).",
				"Create a JSON key for the service account — your browser downloads the key file.",
				"Open the JSON file and paste its entire contents below.",
			},
			Fields: []SetupField{
				{Key: "project_id", Label: "Project ID", Type: SetupFieldText, Required: true, Placeholder: "my-project-123456", Help: "The Google Cloud project ID (not the project name/number)."},
				{Key: "service_account_json", Label: "Service account JSON key", Type: SetupFieldTextarea, Secret: true, Required: true, Placeholder: `{ "type": "service_account", … }`, Help: "Paste the full contents of the service-account JSON key file you downloaded."},
				{Key: "customer_id", Label: "Cloud Identity customer ID", Type: SetupFieldText, Required: false, Placeholder: "C0xxxxxxx", Help: "Optional. Your Cloud Identity / Workspace customer ID, used for directory-wide reads."},
			},
		}},
	},

	"github": {
		Overview: "Connect a GitHub organization with a token that can read its members and teams.",
		DocsURL:  "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
		AuthMethods: []SetupAuthMethod{{
			ID:          "pat",
			Label:       "Personal access token",
			Description: "A token (classic or fine-grained) for a user who is an owner/admin of the organization.",
			DocsURL:     "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
			Recommended: true,
			Steps: []string{
				"Sign in as an owner of the GitHub organization you want to connect.",
				"Go to Settings → Developer settings → Personal access tokens and generate a token.",
				"For a classic token grant the read:org scope; for a fine-grained token grant the org's Members read permission.",
				"Copy the token — GitHub shows it only once. Your organization is the org login (the name in the URL github.com/<org>).",
			},
			Fields: []SetupField{
				{Key: "organization", Label: "Organization", Type: SetupFieldText, Required: true, Placeholder: "your-org", Help: "The GitHub organization login — the name in github.com/<org>, not the display name."},
				{Key: "access_token", Label: "Access token", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "ghp_… or github_pat_…", Help: "A personal access token for an org owner, with read:org (classic) or Members read (fine-grained)."},
			},
		}},
	},

	"cloudflare": {
		Overview: "Connect a Cloudflare account. An API token scoped to the access you need is preferred; a legacy Global API key is also supported.",
		DocsURL:  "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
		AuthMethods: []SetupAuthMethod{
			{
				ID:          "api_token",
				Label:       "API token",
				Description: "A scoped Cloudflare API token (preferred — least privilege, revocable independently).",
				DocsURL:     "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
				Recommended: true,
				Steps: []string{
					"In the Cloudflare dashboard, open My Profile → API Tokens → Create Token.",
					"Use a template or custom token with the read/edit permissions your integration needs (e.g. Account → Access: Apps and Policies).",
					"Copy the token value. Find your Account ID on the dashboard Overview page (right sidebar).",
				},
				Fields: []SetupField{
					{Key: "account_id", Label: "Account ID", Type: SetupFieldText, Required: true, Placeholder: "your account ID", Help: "Your Cloudflare Account ID, shown in the right sidebar of the dashboard Overview."},
					{Key: "team_domain", Label: "Access team name", Type: SetupFieldText, Required: false, Placeholder: "acme", Help: "Optional. Your Cloudflare Access team name (the \"acme\" in acme.cloudflareaccess.com). Enables SAML metadata."},
					{Key: "api_token", Label: "API token", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "the API token value", Help: "The scoped API token you created under My Profile → API Tokens."},
				},
			},
			{
				ID:          "global_api_key",
				Label:       "Global API key (legacy)",
				Description: "Your account email plus the account-wide Global API key. Broad privilege — prefer a scoped token.",
				DocsURL:     "https://developers.cloudflare.com/fundamentals/api/get-started/keys/",
				Steps: []string{
					"In the Cloudflare dashboard, open My Profile → API Tokens → Global API Key and click View.",
					"Copy the key and use the email address you sign in to Cloudflare with.",
					"Find your Account ID on the dashboard Overview page (right sidebar).",
				},
				Fields: []SetupField{
					{Key: "account_id", Label: "Account ID", Type: SetupFieldText, Required: true, Placeholder: "your account ID", Help: "Your Cloudflare Account ID, shown in the right sidebar of the dashboard Overview."},
					{Key: "email", Label: "Account email", Type: SetupFieldEmail, Required: true, Placeholder: "you@example.com", Help: "The email address you sign in to Cloudflare with. Required for the Global API key."},
					{Key: "team_domain", Label: "Access team name", Type: SetupFieldText, Required: false, Placeholder: "acme", Help: "Optional. Your Cloudflare Access team name (the \"acme\" in acme.cloudflareaccess.com)."},
					{Key: "api_key", Label: "Global API key", Type: SetupFieldPassword, Secret: true, Required: true, Placeholder: "the Global API key", Help: "The account-wide Global API key from My Profile → API Tokens. Treat it like a password."},
				},
			},
		},
	},
}

// SetupSchemaFor returns the curated guided-setup schema for a provider, with
// Provider and DisplayName resolved from the live registry so they cannot drift
// from the catalogue. The bool is false when the provider has no curated schema
// (the connect UI then falls back to the manual key/value editor).
func SetupSchemaFor(provider string) (ConnectorSetupSchema, bool) {
	base, ok := connectorSetupSchemas[provider]
	if !ok {
		return ConnectorSetupSchema{}, false
	}
	base.Provider = provider
	if d, ok := CapabilityDescriptorFor(provider); ok {
		base.DisplayName = d.DisplayName
	}
	return base, true
}

// HasSetupSchema reports whether a provider has a curated guided-setup schema.
func HasSetupSchema(provider string) bool {
	_, ok := connectorSetupSchemas[provider]
	return ok
}

// ProvidersWithSetupSchema returns the sorted provider keys that have a curated
// guided-setup schema. It backs the visibility test that tracks coverage as it
// grows.
func ProvidersWithSetupSchema() []string {
	out := make([]string, 0, len(connectorSetupSchemas))
	for p := range connectorSetupSchemas {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
