# ShieldNet ⇄ iam-core Integration Spec (canonical, shared by both repos)

This is the single source of truth for how **fishbone-access** (ShieldNet Access)
and **visible-fishbone** (ShieldNet Gateway) integrate with **uneycom/iam-core**
as their identity provider. All child sessions must follow this contract so the
two products stay consistent. Replaces every Keycloak reference inherited from
cautious-fishstick.

## iam-core facts (verified from uneycom/iam-core protos + server code)

iam-core is a Go (Kratos + Wire + SQLC) multi-tenant OAuth2/OIDC provider.
API is defined in `iam-core-api/api/**/*.proto`. Verified endpoints:

### OAuth2 / OIDC (transport: `internal/server`)
- `GET  /oauth2/authorize`   — authorization endpoint (PKCE mandatory for public clients)
- `POST /oauth2/token`       — token endpoint (auth code + PKCE, refresh, client_credentials)
- `POST /oauth2/introspect`  — RFC 7662 token introspection
- `POST /oauth2/revoke`      — RFC 7009 revocation
- `GET  /oauth2/jwks`        — **JWKS endpoint** (use this for JWT signature validation)
- `GET  /.well-known/openid-configuration`        — OIDC discovery
- `GET  /.well-known/oauth-authorization-server`  — RFC 8414 metadata

### Auth + MFA (`api/auth/v1/auth.proto`)
- `POST /auth/login`, `POST /auth/register`, `POST /auth/change-password`
- `GET  /auth/providers`, `GET /auth/social-identities`
- MFA (TOTP): `POST /auth/mfa/totp/enroll`, `POST /auth/api/mfa/totp/confirm`,
  `GET /auth/mfa/status`, `POST /auth/mfa/totp/disable`,
  `POST /auth/mfa/recovery-codes/generate`
- **NOTE:** there is **no** `/auth/mfa/verify` endpoint (the original plan's
  reference is wrong). MFA is enforced **inside the OIDC/login flow**: when a
  tenant requires MFA, the universal-login flow challenges the user and the
  resulting access token carries an MFA/`amr` claim. For **step-up** in
  ShieldNet (PAM secret reveal, sensitive ops), the correct pattern is:
  (1) read MFA state from token claims (`amr`/custom `mfa` claim); if absent,
  (2) drive a fresh OIDC re-auth (prompt=login + acr/claims requesting MFA) and
  validate the returned token's MFA claim, OR (3) use `/oauth2/introspect` to
  confirm an active, MFA-satisfied session. Do **not** invent a verify endpoint.

### Management API (`api/management/v1/management.proto`) — audience-restricted
- Users:  `GET/POST /api/v1/management/users`, `GET/DELETE /api/v1/management/users/{user_id}`,
  `POST .../users/{user_id}/block`, `POST .../users/{user_id}/unblock`,
  `GET .../users/{user_id}/identities`, `DELETE .../users/{user_id}/identities/{provider}`
- Tenants: `GET/POST /api/v1/management/tenants`, `GET/DELETE /api/v1/management/tenants/{tenant_id}`,
  members CRUD + `bulk-invite` under `/tenants/{tenant_id}/members`
- Orgs: `GET/POST /api/v1/management/organizations`

### Connections / SSO federation (`api/connection/v1/connection.proto`)
- `POST   /api/v1/management/connections`            — create SSO connection
- `GET    /api/v1/management/connections`            — list
- `GET    /api/v1/management/connections/{id}`       — read
- `DELETE /api/v1/management/connections/{id}`       — delete
- `POST   /api/v1/management/connections/{id}/test`  — test connectivity
- `POST   /api/v1/management/connections/{id}/toggle`— enable/disable
- `GET    /api/v1/management/connections/scopes/{provider}`
- **Connection strategies (catalog slugs):** `google-oauth2`, `microsoft`
  (a.k.a. `microsoft-online`), `github`, `discord`, `zoho`, `apple`,
  `apple-native`, `saml`, `oidc` (**generic OIDC — use this for Okta**),
  `username-password`.

## Required integration patterns (both repos)

### 1. JWT validation middleware (shared pattern)
- Fetch + cache JWKS from `${IAM_CORE_ISSUER}/oauth2/jwks` (honor cache headers;
  refresh on unknown `kid`). In Go use `github.com/MicahParks/keyfunc/v3`
  (already a cautious-fishstick dependency) or lestrrat-go/jwx.
- Validate: signature (RS256/ES256 per JWKS), `iss == IAM_CORE_ISSUER`,
  `aud` contains the product's client/audience, `exp`/`nbf`/`iat`.
- Extract claims → request context: `sub` (iam-core user_id), `tenant_id`
  (iam-core tenant), roles/scopes, and MFA state (`amr`/`mfa`).
- Fail-closed. In unit tests, mock the JWKS (generate an in-test RSA key, serve a
  fake JWKS, sign test tokens). Integration tests hit a real iam-core.

### 2. Tenant resolution / isolation
- The `tenant_id` JWT claim is the **sole authoritative** source of the caller's
  tenant. Resolution is fail-closed: a token with no `tenant_id` claim → 403 (do
  NOT fall back to a client-supplied header; that would let any authenticated
  principal act as any tenant). The `X-Tenant-ID` header is advisory only —
  when present it must equal the claim, otherwise 403 (mismatch).
- Cross-tenant / platform-operator flows are a **separate, explicitly authorized
  path** (a dedicated management route that checks a platform scope/role and
  then reads `X-Tenant-ID`), never an implicit header fallback in the shared
  tenant-resolution middleware.
- **fishbone-access:** map iam-core `tenant_id` → `workspace` isolation (every
  query scoped by workspace_id).
- **visible-fishbone:** map iam-core `tenant_id` → existing SNG tenant model
  (`internal/service/tenant/`), preserving Postgres RLS GUC `sng.tenant_id`.

### 3. SSO federation = iam-core Connections (NOT Keycloak)
- To configure SSO for a customer's IdP, create an iam-core **Connection** via
  `POST /api/v1/management/connections` with the right strategy slug. Map the
  connector/IdP type → strategy: Entra/Azure AD → `microsoft`; Google Workspace
  → `google-oauth2`; Okta/Ping/OneLogin/JumpCloud/Auth0 → `oidc` (generic);
  Zoho → `zoho`; GitHub → `github`.

### 4. SCIM bridge (visible-fishbone specific, Session 2A)
- iam-core has no SCIM inbound yet. SNG already exposes SCIM 2.0
  (`internal/service/identity/scim.go`). Wire SNG's SCIM create/update/delete →
  iam-core Management API (`POST/GET/DELETE /api/v1/management/users`,
  block/unblock for deactivate). SNG remains the SCIM endpoint; iam-core stores
  identity.

### 5. MFA enforcement / step-up
- Read MFA requirement from token claims per tenant. For step-up, re-run OIDC
  with MFA-requesting claims or introspect; never call a nonexistent verify
  endpoint (see NOTE above).

### 6. Endpoint clients (visible-fishbone `crates/sng-oidc`, Session 2E)
- Point PKCE flow at iam-core `/.well-known/openid-configuration` for discovery
  and `/oauth2/authorize` + `/oauth2/token`. Handle the MFA-challenge path
  surfaced by the universal-login flow.

## Config contract (env vars, both repos)
```
IAM_CORE_ISSUER            = https://<iam-core-host>            # base, hosts /oauth2/* and /.well-known/*
IAM_CORE_JWKS_URL          = ${IAM_CORE_ISSUER}/oauth2/jwks     # derive if unset
IAM_CORE_OIDC_DISCOVERY    = ${IAM_CORE_ISSUER}/.well-known/openid-configuration
IAM_CORE_CLIENT_ID         = <product oauth2 client id>
IAM_CORE_CLIENT_SECRET     = <product oauth2 client secret>     # confidential client
IAM_CORE_AUDIENCE          = <expected aud claim>
IAM_CORE_MGMT_BASE_URL     = ${IAM_CORE_ISSUER}                 # /api/v1/management/*
IAM_CORE_MGMT_TOKEN        = <client_credentials token for mgmt audience>
```
Mgmt API calls authenticate with a `client_credentials` token minted at
`/oauth2/token` for the management audience; cache + refresh before expiry.

## Hard rules
- No Keycloak anywhere. No runtime dependency between fishbone-access and
  cautious-fishstick (cautious-fishstick is read-only reference only).
- Secrets encrypted at rest (AES-GCM). Inter-service over TLS/mTLS. Tenant
  isolation enforced at every layer. No stubs — real API calls, real tests;
  mock iam-core only in unit tests.
