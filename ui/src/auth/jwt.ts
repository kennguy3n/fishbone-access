// Best-effort decode of a JWT payload for display purposes only.
// The control plane is the authority on token validity — the SPA never
// trusts these claims for authorization, it only uses them to render the
// signed-in user's name and any tenant hints.

export interface JwtClaims {
  sub?: string;
  email?: string;
  name?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  tenant_id?: string;
  scopes?: string[];
  roles?: string[];
  [k: string]: unknown;
}

export function decodeJwt(token: string): JwtClaims | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payload.padEnd(
      payload.length + ((4 - (payload.length % 4)) % 4),
      "=",
    );
    return JSON.parse(atob(padded)) as JwtClaims;
  } catch {
    return null;
  }
}

export function isExpired(claims: JwtClaims | null): boolean {
  // Distinguish "no exp claim" from exp:0: use == null so a token with
  // exp:0 (expired at the Unix epoch) is correctly treated as expired
  // rather than as "never expires".
  if (claims?.exp == null) return false;
  return claims.exp * 1000 <= Date.now();
}
