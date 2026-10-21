import { ApiError } from "../errors.ts";
import type { IdentityProvider } from "./types.ts";

/**
 * DEVELOPMENT / TEST ONLY. Stands in for Google so the whole sign-in flow can be exercised without credentials.
 * Refused by `loadConfig` in staging and production; its pages are only served in development/test.
 * The "code" it issues is just the email address the developer typed, so it can never be mistaken for a real login.
 */
export class MockIdentity implements IdentityProvider {
  readonly name = "mock" as const;
  private apiUrl: string;
  constructor(apiUrl: string) {
    this.apiUrl = apiUrl;
  }
  authorizationUrl(i: { state: string }) {
    return `${this.apiUrl}/dev/mock-signin?${new URLSearchParams({ state: i.state })}`;
  }
  async exchange(i: { code: string }) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(i.code)) throw new ApiError(403, "signin_denied", "mock sign-in needs an email address");
    return { email: i.code.toLowerCase() };
  }
}
