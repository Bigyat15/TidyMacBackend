import { ApiError } from "../errors.ts";
import type { IdentityProvider, VerifiedIdentity } from "./types.ts";

const ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

/** Reads the claims of an ID token we received DIRECTLY from Google's token endpoint over TLS (OIDC Core 3.1.3.7 permits this without checking the JWT signature). */
export function claimsOf(idToken: string): Record<string, any> {
  const part = idToken.split(".")[1];
  if (!part) throw new ApiError(502, "identity_error", "Google returned an invalid ID token");
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    throw new ApiError(502, "identity_error", "Google returned an unreadable ID token");
  }
}

/** Every check that makes a Google sign-in trustworthy; unit-tested one by one. */
export function validateClaims(c: Record<string, any>, o: { clientId: string; nonce: string; nowSec: number }): VerifiedIdentity {
  const bad = (m: string) => new ApiError(403, "signin_denied", m);
  if (!ISSUERS.includes(c.iss)) throw bad("sign-in came from an unexpected issuer");
  if (c.aud !== o.clientId) throw bad("sign-in was issued for a different app");
  if (typeof c.exp !== "number" || c.exp <= o.nowSec) throw bad("sign-in has expired");
  if (c.nonce !== o.nonce) throw bad("sign-in did not match this login attempt");
  if (c.email_verified !== true) throw bad("your Google email address is not verified");
  if (typeof c.email !== "string" || !c.email.includes("@")) throw bad("Google did not share an email address");
  return { email: c.email.toLowerCase() };
}

export class GoogleIdentity implements IdentityProvider {
  readonly name = "google" as const;
  private clientId: string;
  private clientSecret: string;
  private f: typeof fetch;
  constructor(o: { clientId: string; clientSecret: string; fetchImpl?: typeof fetch }) {
    this.clientId = o.clientId;
    this.clientSecret = o.clientSecret;
    this.f = o.fetchImpl ?? fetch;
  }

  authorizationUrl(i: { redirectUri: string; state: string; nonce: string; codeChallenge: string }) {
    const q = new URLSearchParams({
      client_id: this.clientId, redirect_uri: i.redirectUri, response_type: "code", scope: "openid email", state: i.state,
      nonce: i.nonce, code_challenge: i.codeChallenge, code_challenge_method: "S256", prompt: "select_account",
    });
    return `https://accounts.google.com/o/oauth2/v2/auth?${q}`;
  }

  async exchange(i: { code: string; redirectUri: string; codeVerifier: string; nonce: string; nowSec: number }) {
    const r = await this.f("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ code: i.code, client_id: this.clientId, client_secret: this.clientSecret, redirect_uri: i.redirectUri, grant_type: "authorization_code", code_verifier: i.codeVerifier }),
    });
    if (!r.ok) throw new ApiError(403, "signin_denied", "Google did not accept the sign-in");
    const j = (await r.json()) as { id_token?: string };
    if (!j.id_token) throw new ApiError(502, "identity_error", "Google returned no ID token");
    return validateClaims(claimsOf(j.id_token), { clientId: this.clientId, nonce: i.nonce, nowSec: i.nowSec });
  }
}
