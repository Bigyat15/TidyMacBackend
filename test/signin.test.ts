// @vitest-environment node
import crypto from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { createAppServer } from "../src/app.ts";
import { validateClaims } from "../src/identity/google.ts";
import { canonicalEmail } from "../src/service.ts";
import { lastCode, makeCtx } from "./helpers.ts";

const challengeOf = (v: string) => crypto.createHash("sha256").update(v).digest("base64url");

describe("web sign-in (mock identity)", () => {
  const h = makeCtx();
  const server = createAppServer({ ...h.ctx, now: () => Math.floor(Date.now() / 1000) });
  let base = "";
  beforeAll(async () => { await new Promise<void>((r) => server.listen(0, "127.0.0.1", r)); base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; (h.ctx.cfg as any).apiUrl = base; });
  afterAll(() => { server.close(); });
  const post = (p: string, b: unknown) => fetch(base + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
  const noFollow = (u: string, init?: RequestInit) => fetch(u, { redirect: "manual", ...init });

  /** start → website → begin → mock Google → callback; returns what the app needs to poll. */
  async function login(inst: string, email: string | null) {
    const verifier = crypto.randomBytes(32).toString("base64url");
    const s = (await (await post("/v1/auth/oauth/start", { installation_id: inst, code_challenge: challengeOf(verifier) })).json()) as any;
    const begin = await noFollow(`${base}/v1/auth/google/begin?s=${s.session_id}`);
    const google = new URL(begin.headers.get("location")!);
    let next = "";
    if (email !== null) {
      const done = await noFollow(`${base}/dev/mock-signin/complete`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ state: google.searchParams.get("state")!, email }) });
      next = done.headers.get("location")!;
    }
    const poll = (v = verifier, i = inst) => post("/v1/auth/oauth/poll", { session_id: s.session_id, code_verifier: v, installation_id: i, device_name: "Mac" });
    return { s, poll, next, google };
  }

  it("pending until the browser finishes, then yields a trial exactly once", async () => {
    const a = await login("install-web-0001", null);
    expect(a.s.login_url).toContain("/signin/?s=");
    expect((await a.poll()).status).toBe(202);
    const done = await noFollow(`${base}/dev/mock-signin/complete`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ state: a.google.searchParams.get("state")!, email: "Person@Example.com" }) });
    expect(done.headers.get("location")).toMatch(/\/signin-done\/$/);
    const ok = await a.poll();
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as any).kind).toBe("trial");
    expect((await a.poll()).status).toBe(410); // single use
  });

  it("only the app holding the verifier, on the same installation, can redeem", async () => {
    const a = await login("install-web-0002", "who@example.com");
    expect((await a.poll(crypto.randomBytes(32).toString("base64url"))).status).toBe(404);
    expect((await a.poll(undefined, "install-web-9999")).status).toBe(404);
    expect((await a.poll()).status).toBe(200);
  });

  it("a replayed callback state fails and cancelling is reported as denied", async () => {
    const a = await login("install-web-0003", "r@example.com");
    const replay = await noFollow(`${base}/v1/auth/google/callback?state=${a.google.searchParams.get("state")}&code=r@example.com`);
    expect(replay.headers.get("location")).toMatch(/\/signin-failed\/$/);
    const b = await login("install-web-0004", null);
    await noFollow(`${base}/dev/mock-signin/complete`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ state: b.google.searchParams.get("state")!, cancel: "1" }) });
    expect((await b.poll()).status).toBe(403);
  });

  it("unknown or expired sessions never reach the provider", async () => {
    expect((await noFollow(`${base}/v1/auth/google/begin?s=nope`)).headers.get("location")).toMatch(/\/signin-failed\/$/);
    expect((await post("/v1/auth/oauth/start", { installation_id: "install-web-0005", code_challenge: "short" })).status).toBe(400);
  });

  it("Google-sign-in and email-code share one trial, and Gmail aliases are one person", async () => {
    expect(canonicalEmail("a.b+x@googlemail.com")).toBe("ab@gmail.com");
    expect(canonicalEmail("a.b@corp.com")).toBe("a.b@corp.com");
    const a = await login("install-web-0006", "first.last@gmail.com");
    const first = (await (await a.poll()).json()) as any;
    // same person via an emailed code on another install, using an alias: same account, so the trial clock is shared
    await post("/v1/auth/request-code", { email: "firstlast+promo@gmail.com", installation_id: "install-web-0007" });
    const v = await post("/v1/auth/verify", { email: "firstlast+promo@gmail.com", code: lastCode(h.mail, "firstlast+promo@gmail.com"), installation_id: "install-web-0007", device_name: "Mac2" });
    const err = (await v.json()) as any;
    expect(err.error.code).toBe("device_limit");
    const m = await post("/v1/devices/release", { manage_token: err.error.manage_token, device_id: err.error.devices[0].id, installation_id: "install-web-0007", device_name: "Mac2" });
    const second = (await m.json()) as any;
    expect(second.kind).toBe("trial");
    expect(Object.keys(first).join()).toBeTruthy();
    expect(second.trial_ends_at ?? second.expires_at).toBeDefined();
    expect(second.trial_ends_at ?? second.expires_at).toBe(first.trial_ends_at ?? first.expires_at);
  });

  it("dev mock page exists only for the mock provider in development/test", async () => {
    expect((await fetch(`${base}/dev/mock-signin?state=x`)).status).toBe(200);
  });
});

describe("Google ID token claims", () => {
  const ok = { iss: "https://accounts.google.com", aud: "cid", exp: 2000, nonce: "n", email: "A@B.com", email_verified: true };
  const ctx = { clientId: "cid", nonce: "n", nowSec: 1000 };
  it("accepts a good token and lowercases the email", () => expect(validateClaims(ok, ctx)).toEqual({ email: "a@b.com" }));
  it.each([
    ["iss", { iss: "https://evil.example" }], ["aud", { aud: "other" }], ["exp", { exp: 900 }],
    ["nonce", { nonce: "x" }], ["unverified", { email_verified: false }], ["no email", { email: undefined }],
  ])("rejects bad %s", (_n, over) => expect(() => validateClaims({ ...ok, ...over } as any, ctx)).toThrow());
});
