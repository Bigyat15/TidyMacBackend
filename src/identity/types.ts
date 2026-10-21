/** An external identity provider (Sign in with Google). Core licensing only sees a verified email. */
export interface VerifiedIdentity {
  email: string;
}

export interface IdentityProvider {
  readonly name: "google" | "mock";
  /** URL the browser is sent to. `redirectUri` is our callback; `state`/`nonce`/`challenge` are generated per login. */
  authorizationUrl(i: { redirectUri: string; state: string; nonce: string; codeChallenge: string }): string;
  /** Exchanges the callback `code` for a VERIFIED identity or throws ApiError. */
  exchange(i: { code: string; redirectUri: string; codeVerifier: string; nonce: string; nowSec: number }): Promise<VerifiedIdentity>;
}
