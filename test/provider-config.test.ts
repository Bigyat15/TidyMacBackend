// @vitest-environment node
import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../src/config.ts";
import { PaddleProvider, parsePaddleEvent } from "../src/providers/paddle.ts";
import { signWebhookBody } from "../src/providers/signing.ts";
import { MockProvider } from "../src/providers/mock.ts";
import { generateKeyPair } from "../src/crypto.ts";

const good = () => ({
  APP_ENV: "production", PAYMENT_PROVIDER: "paddle", PADDLE_MODE: "live", PADDLE_API_KEY: "k", PADDLE_WEBHOOK_SECRET: "s", PADDLE_PRICE_ID: "pri_1",
  EMAIL_PROVIDER: "resend", EMAIL_FROM: "TidyMac <hello@example.com>", RESEND_API_KEY: "r", WEBSITE_URL: "https://tidymac.example", LICENSE_API_URL: "https://api.tidymac.example",
  DATABASE_PATH: "/var/data/lic.sqlite", LICENSE_SIGNING_PRIVATE_KEY: generateKeyPair().privateKeyB64, CODE_HMAC_SECRET: "c".repeat(40), LICENSE_KEY_SECRET: "k".repeat(40), ALLOWED_ORIGINS: "https://tidymac.example",
  IDENTITY_PROVIDER: "google", GOOGLE_CLIENT_ID: "id.apps.googleusercontent.com", GOOGLE_CLIENT_SECRET: "gs",
});
const problems = (e: Record<string, string>) => { try { loadConfig(e); } catch (x) { return (x as ConfigError).problems.join("\n"); } return ""; };

describe("configuration fails closed", () => {
  it("accepts a complete production config and marks entitlements live", () => {
    const c = loadConfig(good());
    expect(c.entitlementMode).toBe("live");
    expect(c.provider).toMatchObject({ name: "paddle", mode: "live" });
  });
  it("refuses to start production with anything missing", () => {
    for (const k of Object.keys(good())) {
      if (k === "ALLOWED_ORIGINS" || k === "APP_ENV") continue;
      const e: Record<string, string> = good(); delete e[k];
      expect(problems(e), `missing ${k}`).not.toBe("");
    }
  });
  it("never allows the mock provider, console mail, http URLs, in-memory db or dev secrets in production", () => {
    expect(problems({ ...good(), PAYMENT_PROVIDER: "mock" })).toContain("mock");
    expect(problems({ ...good(), EMAIL_PROVIDER: "console" })).toContain("console");
    expect(problems({ ...good(), WEBSITE_URL: "http://tidymac.example" })).toContain("https");
    expect(problems({ ...good(), DATABASE_PATH: ":memory:" })).toContain("memory");
    expect(problems({ ...good(), CODE_HMAC_SECRET: "dev-only-" + "x".repeat(40) })).toContain("development secrets");
    expect(problems({ ...good(), PADDLE_MODE: "sandbox" })).toContain("PADDLE_MODE=live");
    expect(problems({ APP_ENV: "production" })).toContain("PAYMENT_PROVIDER");
    expect(problems({ ...good(), IDENTITY_PROVIDER: "mock" })).toContain("mock");
    expect(problems({ ...good(), GOOGLE_CLIENT_SECRET: "" })).toContain("GOOGLE_CLIENT_SECRET");
  });
  it("staging must use the sandbox and never produces live entitlements", () => {
    expect(problems({ ...good(), APP_ENV: "staging" })).toContain("sandbox");
    const c = loadConfig({ ...good(), APP_ENV: "staging", PADDLE_MODE: "sandbox" });
    expect(c.entitlementMode).toBe("test");
  });
  it("development defaults to mock payments and test entitlements", () => {
    const c = loadConfig({ APP_ENV: "development" });
    expect(c.provider.name).toBe("mock");
    expect(c.entitlementMode).toBe("test");
  });
});

describe("Paddle adapter", () => {
  const opts = { apiKey: "key_123", webhookSecret: "whsec", priceId: "pri_1", toleranceSec: 300 };
  const body = JSON.stringify({ event_id: "evt_01", event_type: "transaction.completed", data: { id: "txn_1", customer_id: "ctm_1", currency_code: "USD", items: [{ price: { id: "pri_1" } }], details: { totals: { total: "2499" } }, custom_data: { checkout_id: "chk_1" } } });
  const sig = (ts: number, raw = body, secret = "whsec") => `ts=${ts};h1=${signWebhookBody(secret, ts, raw)}`;
  const p = new PaddleProvider({ ...opts, mode: "sandbox" });

  it("verifies Paddle's ts/h1 HMAC over `ts:rawBody`", () => {
    const now = 1_800_000_000;
    expect(() => p.verifyWebhook(body, { "paddle-signature": sig(now) }, now)).not.toThrow();
    expect(() => p.verifyWebhook(body, { "paddle-signature": sig(now, body, "other") }, now)).toThrow(/mismatch/);
    expect(() => p.verifyWebhook(body + "\n", { "paddle-signature": sig(now) }, now)).toThrow();
    expect(() => p.verifyWebhook(body, { "paddle-signature": sig(now - 1000) }, now)).toThrow(/stale/);
    expect(() => p.verifyWebhook(body, { "paddle-signature": `ts=${now};h1=00;h1=${signWebhookBody("whsec", now, body)}` }, now)).not.toThrow(); // any h1 may match
    expect(() => p.verifyWebhook(body, {}, now)).toThrow(/missing/);
  });

  it("maps events to the provider-independent model", () => {
    expect(parsePaddleEvent(body)).toMatchObject({ eventId: "evt_01", type: "purchase_completed", orderId: "txn_1", priceId: "pri_1", amountMinor: 2499, checkoutId: "chk_1" });
    const adj = (action: string, type: string, status = "approved") => parsePaddleEvent(JSON.stringify({ event_id: "evt_a", event_type: "adjustment.created", data: { status, action, type, transaction_id: "txn_1" } }));
    expect(adj("refund", "full").type).toBe("purchase_refunded");
    expect(adj("refund", "partial").type).toBe("ignored");
    expect(adj("chargeback", "full").type).toBe("purchase_chargeback");
    expect(adj("refund", "full", "pending_approval").type).toBe("ignored");
    expect(parsePaddleEvent(JSON.stringify({ event_id: "e", event_type: "subscription.created", data: {} })).type).toBe("ignored");
    expect(() => parsePaddleEvent("not json")).toThrow();
  });

  it("re-verifies a purchase through the API (and looks up the buyer's email)", async () => {
    const calls: { url: string; auth: string }[] = [];
    const f = (async (url: string, init: any) => {
      calls.push({ url, auth: init.headers.Authorization });
      const data = url.includes("/customers/") ? { email: "buyer@example.com" } : { status: "completed", customer_id: "ctm_1", currency_code: "USD", items: [{ price: { id: "pri_1" } }], details: { totals: { total: "2499" } } };
      return new Response(JSON.stringify({ data }), { status: 200 });
    }) as any;
    const facts = await new PaddleProvider({ ...opts, mode: "sandbox", fetchImpl: f }).verifyPurchase("txn_1");
    expect(facts).toMatchObject({ completed: true, email: "buyer@example.com", priceId: "pri_1", amountMinor: 2499 });
    expect(calls[0].url).toBe("https://sandbox-api.paddle.com/transactions/txn_1");
    expect(calls[0].auth).toBe("Bearer key_123");
    const live = await new PaddleProvider({ ...opts, mode: "live", fetchImpl: f }).verifyPurchase("txn_1");
    expect(calls.at(-1)!.url.startsWith("https://api.paddle.com/")).toBe(true);
    expect(live.completed).toBe(true);
  });

  it("creates a checkout from the SERVER-configured price and surfaces provider failures", async () => {
    let sent: any;
    const ok = (async (_u: string, init: any) => { sent = JSON.parse(init.body); return new Response(JSON.stringify({ data: { id: "txn_9", checkout: { url: "https://pay.example/c/1" } } }), { status: 200 }); }) as any;
    const r = await new PaddleProvider({ ...opts, mode: "sandbox", fetchImpl: ok }).createCheckout({ checkoutId: "chk_1" });
    expect(r.url).toBe("https://pay.example/c/1");
    expect(sent.items).toEqual([{ price_id: "pri_1", quantity: 1 }]);
    expect(sent.custom_data).toEqual({ checkout_id: "chk_1" });
    const noLink = (async () => new Response(JSON.stringify({ data: { id: "t" } }), { status: 200 })) as any;
    await expect(new PaddleProvider({ ...opts, mode: "sandbox", fetchImpl: noLink }).createCheckout({ checkoutId: "c" })).rejects.toMatchObject({ code: "checkout_unavailable" });
    const bad = (async () => new Response("{}", { status: 403 })) as any;
    await expect(new PaddleProvider({ ...opts, mode: "sandbox", fetchImpl: bad }).verifyPurchase("t")).rejects.toMatchObject({ code: "provider_error" });
  });

  it("the mock adapter's events are not accepted by the real adapter (different secret)", () => {
    const m = new MockProvider("http://x", "mock-secret", 300);
    const f = m.fixture("completed", { eventId: "evt_m", orderId: "txn_m", email: "a@b.co", ts: 1_800_000_000 });
    expect(() => p.verifyWebhook(f.raw, f.headers, 1_800_000_000)).toThrow(/mismatch/);
  });
});
