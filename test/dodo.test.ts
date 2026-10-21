// @vitest-environment node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { createAppServer } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { openDb } from "../src/db.ts";
import { DodoProvider, signStandardWebhook } from "../src/providers/dodo.ts";
import * as svc from "../src/service.ts";
import { lastKey, makeCtx, T0 } from "./helpers.ts";

const PRODUCT = "pdt_tidymac_pro";
const SECRET = "whsec_" + Buffer.from("dodo-test-signing-key-0123456789").toString("base64");

/** A fake Dodo API: records requests, answers /checkouts and /payments/{id}. */
function fakeDodo() {
  const calls: { path: string; method: string; auth: string; body: any }[] = [];
  const payments = new Map<string, any>();
  const f = (async (url: string, init: RequestInit = {}) => {
    const p = new URL(url).pathname;
    calls.push({ path: p, method: init.method ?? "GET", auth: String((init.headers as any)?.Authorization), body: init.body ? JSON.parse(String(init.body)) : undefined });
    if (p === "/checkouts") return new Response(JSON.stringify({ session_id: "cks_1", checkout_url: "https://test.checkout.dodopayments.com/session/cks_1" }), { status: 200 });
    const m = p.match(/^\/payments\/(.+)$/);
    if (m && payments.has(m[1])) return new Response(JSON.stringify(payments.get(m[1])), { status: 200 });
    return new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
  return { f, calls, payments };
}

const payment = (id: string, o: Record<string, unknown> = {}) => ({ payment_id: id, status: "succeeded", total_amount: 999, currency: "USD", customer: { customer_id: "cus_d1", email: "Buyer@Example.com" }, product_cart: [{ product_id: PRODUCT, quantity: 1 }], ...o });

function setup(dbPath = ":memory:") {
  const h = makeCtx({}, dbPath);
  const api = fakeDodo();
  const provider = new DodoProvider({ apiKey: "test_key", webhookSecret: SECRET, productId: PRODUCT, returnUrl: "https://site.example/purchase-success/", mode: "sandbox", toleranceSec: 300, fetchImpl: api.f });
  const ctx = { ...h.ctx, provider, priceId: PRODUCT };
  let n = 0;
  /** Builds a correctly signed Standard Webhooks delivery. */
  const delivery = (type: string, data: Record<string, unknown>, o: { id?: string; ts?: number; secret?: string } = {}) => {
    const raw = JSON.stringify({ business_id: "bus_x", type, timestamp: new Date(T0 * 1000).toISOString(), data });
    const id = o.id ?? `msg_${++n}`, ts = o.ts ?? h.clock.t;
    return { raw, headers: { "webhook-id": id, "webhook-timestamp": String(ts), "webhook-signature": signStandardWebhook(o.secret ?? SECRET, id, ts, raw) } };
  };
  const send = (type: string, data: Record<string, unknown>, o?: Parameters<typeof delivery>[2]) => { const d = delivery(type, data, o); return svc.handleWebhook(ctx, d.raw, d.headers); };
  const count = (t: string) => Number((ctx.db.prepare(`SELECT COUNT(*) c FROM ${t}`).get() as any).c);
  const licenseStatus = () => (ctx.db.prepare("SELECT status FROM licenses").get() as any)?.status;
  return { h, ctx, api, delivery, send, count, licenseStatus };
}

describe("Dodo checkout", () => {
  it("creates a pending checkout record and a session for the SERVER-chosen product", async () => {
    const t = setup();
    const r = await svc.createCheckout(t.ctx, { email: "buyer@example.com", ip: "ip1", product_id: "pdt_evil", price: 1, amount: 1 } as any);
    expect(r.url).toBe("https://test.checkout.dodopayments.com/session/cks_1");
    expect(r.test_mode).toBe(true);
    const call = t.api.calls[0];
    expect(call.path).toBe("/checkouts");
    expect(call.auth).toBe("Bearer test_key");
    expect(call.body.product_cart).toEqual([{ product_id: PRODUCT, quantity: 1 }]); // nothing from the client reaches the cart
    expect(JSON.stringify(call.body)).not.toMatch(/evil|"price"|"amount"/);
    expect(call.body.metadata).toEqual({ checkout_id: r.checkout_id });
    expect(call.body.return_url).toContain(`checkout_id=${r.checkout_id}`);
    expect(call.body.customer).toEqual({ email: "buyer@example.com" });
    const row = t.ctx.db.prepare("SELECT status, provider, provider_ref FROM checkouts WHERE id = ?").get(r.checkout_id) as any;
    expect(row).toMatchObject({ status: "created", provider: "dodo", provider_ref: "cks_1" });
    expect(svc.checkoutStatus(t.ctx, r.checkout_id)).toEqual({ status: "pending" }); // a success PAGE never unlocks anything
    expect(t.count("licenses")).toBe(0);
  });
  it("fails closed when the provider gives no URL or errors", async () => {
    const t = setup();
    const bad = new DodoProvider({ apiKey: "k", webhookSecret: SECRET, productId: PRODUCT, returnUrl: "https://x/", mode: "sandbox", toleranceSec: 300, fetchImpl: (async () => new Response("{}", { status: 500 })) as any });
    await expect(bad.createCheckout({ checkoutId: "c" })).rejects.toMatchObject({ code: "provider_error" });
    const noUrl = new DodoProvider({ apiKey: "k", webhookSecret: SECRET, productId: PRODUCT, returnUrl: "https://x/", mode: "sandbox", toleranceSec: 300, fetchImpl: (async () => new Response("{}", { status: 200 })) as any });
    await expect(noUrl.createCheckout({ checkoutId: "c" })).rejects.toMatchObject({ code: "checkout_unavailable" });
    expect(t.count("licenses")).toBe(0);
  });
  it("uses the live API host only in live mode", () => {
    const mk = (mode: "sandbox" | "live") => (new DodoProvider({ apiKey: "k", webhookSecret: SECRET, productId: PRODUCT, returnUrl: "https://x/", mode, toleranceSec: 300, fetchImpl: ((u: string) => { (mk as any).seen = u; return Promise.resolve(new Response('{"checkout_url":"u"}')); }) as any }));
    void mk("sandbox").createCheckout({ checkoutId: "c" });
    expect((mk as any).seen).toContain("https://test.dodopayments.com/");
    void mk("live").createCheckout({ checkoutId: "c" });
    expect((mk as any).seen).toContain("https://live.dodopayments.com/");
  });
});

describe("Dodo webhooks: authenticity", () => {
  it("rejects a missing, forged, tampered, stale or wrong-secret signature and unlocks nothing", async () => {
    const t = setup();
    const good = t.delivery("payment.succeeded", payment("pay_1"));
    const attempts: [string, string, Record<string, string>][] = [
      ["no headers", good.raw, {}],
      ["tampered body", good.raw.replace("999", "1"), good.headers],
      ["wrong secret", ...(() => { const d = t.delivery("payment.succeeded", payment("pay_1"), { secret: "whsec_" + Buffer.from("another-secret-another-secret-12").toString("base64") }); return [d.raw, d.headers] as [string, Record<string, string>]; })()],
      ["stale", ...(() => { const d = t.delivery("payment.succeeded", payment("pay_1"), { ts: T0 - 3600 }); return [d.raw, d.headers] as [string, Record<string, string>]; })()],
      ["garbage signature", good.raw, { ...good.headers, "webhook-signature": "v1,AAAA" }],
    ];
    for (const [name, raw, headers] of attempts) await expect(svc.handleWebhook(t.ctx, raw, headers), name).rejects.toMatchObject({ status: 401 });
    expect(t.count("purchases") + t.count("licenses") + t.count("webhook_events")).toBe(0);
  });
  it("accepts a multi-signature header when any v1 matches (key rotation)", async () => {
    const t = setup();
    t.api.payments.set("pay_r", payment("pay_r"));
    const d = t.delivery("payment.succeeded", payment("pay_r"));
    const headers = { ...d.headers, "webhook-signature": `v1,AAAA ${d.headers["webhook-signature"]}` };
    expect((await svc.handleWebhook(t.ctx, d.raw, headers)).status).toBe("processed");
  });
  it("over HTTP: a bad signature gets 401 and the wrong provider path 404", async () => {
    const t = setup();
    const server = createAppServer(t.ctx);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const d = t.delivery("payment.succeeded", payment("pay_h"));
    const post = (p: string, headers: Record<string, string>) => fetch(base + p, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: d.raw });
    expect((await post("/v1/webhooks/dodo", { ...d.headers, "webhook-signature": "v1,AAAA" })).status).toBe(401);
    expect((await post("/v1/webhooks/paddle", d.headers)).status).toBe(404);
    t.api.payments.set("pay_h", payment("pay_h"));
    expect((await post("/v1/webhooks/dodo", d.headers)).status).toBe(200);
    expect(t.count("licenses")).toBe(1);
    server.close();
  });
});

describe("Dodo webhooks: fulfillment", () => {
  it("a verified payment.succeeded issues exactly one license and emails the key", async () => {
    const t = setup();
    const c = await svc.createCheckout(t.ctx, { email: "buyer@example.com", ip: "ip" });
    t.api.payments.set("pay_1", payment("pay_1", { metadata: { checkout_id: c.checkout_id } }));
    expect((await t.send("payment.succeeded", payment("pay_1", { metadata: { checkout_id: c.checkout_id } }))).status).toBe("processed");
    expect(t.count("purchases")).toBe(1);
    expect(t.count("licenses")).toBe(1);
    expect(t.licenseStatus()).toBe("active");
    expect(lastKey(t.h.mail)).toMatch(/^TM-/);
    expect(svc.checkoutStatus(t.ctx, c.checkout_id)).toEqual({ status: "confirmed" });
    expect((t.ctx.db.prepare("SELECT provider, provider_order_id, simulated FROM purchases").get() as any)).toMatchObject({ provider: "dodo", provider_order_id: "pay_1", simulated: 0 });
  });
  it("replays are harmless: same webhook-id is a duplicate, a new id for the same payment issues nothing new", async () => {
    const t = setup();
    t.api.payments.set("pay_1", payment("pay_1"));
    const d = t.delivery("payment.succeeded", payment("pay_1"), { id: "msg_fixed" });
    expect((await svc.handleWebhook(t.ctx, d.raw, d.headers)).status).toBe("processed");
    expect((await svc.handleWebhook(t.ctx, d.raw, d.headers)).status).toBe("duplicate");
    expect((await t.send("payment.succeeded", payment("pay_1"), { id: "msg_other" })).status).toBe("processed");
    expect(t.count("purchases")).toBe(1);
    expect(t.count("licenses")).toBe(1);
    expect(t.h.mail.outbox.filter((m) => /license/i.test(m.subject)).length).toBe(1);
  });
  it("failed, cancelled and processing payments unlock nothing", async () => {
    const t = setup();
    for (const type of ["payment.failed", "payment.cancelled", "payment.processing"]) expect((await t.send(type, payment("pay_x", { status: "failed" }))).status).toBe("ignored");
    expect(t.count("purchases") + t.count("licenses")).toBe(0);
  });
  it("trusts Dodo's API over the webhook body: a payment Dodo does not report as succeeded unlocks nothing", async () => {
    const t = setup();
    t.api.payments.set("pay_1", payment("pay_1", { status: "failed" }));
    expect((await t.send("payment.succeeded", payment("pay_1"))).status).toBe("ignored");
    expect(t.count("licenses")).toBe(0);
  });
  it("ignores the wrong product, a multi-item cart, and a payment Dodo cannot confirm", async () => {
    const t = setup();
    t.api.payments.set("pay_w", payment("pay_w", { product_cart: [{ product_id: "pdt_other", quantity: 1 }] }));
    expect((await t.send("payment.succeeded", payment("pay_w", { product_cart: [{ product_id: "pdt_other", quantity: 1 }] }))).status).toBe("ignored");
    const multi = payment("pay_m", { product_cart: [{ product_id: PRODUCT, quantity: 1 }, { product_id: "pdt_extra", quantity: 1 }] });
    t.api.payments.set("pay_m", multi);
    expect((await t.send("payment.succeeded", multi)).status).toBe("ignored");
    await expect(t.send("payment.succeeded", payment("pay_unknown"))).rejects.toMatchObject({ status: 500, code: "webhook_failed" }); // Dodo 404 => marked failed, retried later, nothing granted
    expect(t.count("licenses")).toBe(0);
  });
});

describe("Dodo refunds and disputes", () => {
  async function paid() {
    const t = setup();
    t.api.payments.set("pay_1", payment("pay_1"));
    await t.send("payment.succeeded", payment("pay_1"));
    expect(t.licenseStatus()).toBe("active");
    return t;
  }
  it("a full refund revokes the license; a partial refund does not", async () => {
    const t = await paid();
    expect((await t.send("refund.succeeded", { refund_id: "re_1", payment_id: "pay_1", is_partial: true })).status).toBe("ignored");
    expect(t.licenseStatus()).toBe("active");
    expect((await t.send("refund.succeeded", { refund_id: "re_2", payment_id: "pay_1", is_partial: false })).status).toBe("processed");
    expect(t.licenseStatus()).toBe("revoked");
    expect((t.ctx.db.prepare("SELECT status FROM purchases").get() as any).status).toBe("refunded");
  });
  it("disputes: opened/won/cancelled keep access; lost or accepted revoke it", async () => {
    const t = await paid();
    for (const type of ["dispute.opened", "dispute.challenged", "dispute.won", "dispute.cancelled", "dispute.expired"]) await t.send(type, { dispute_id: "dp_1", payment_id: "pay_1" });
    expect(t.licenseStatus()).toBe("active");
    await t.send("dispute.lost", { dispute_id: "dp_1", payment_id: "pay_1" });
    expect(t.licenseStatus()).toBe("revoked");
    expect((t.ctx.db.prepare("SELECT status FROM purchases").get() as any).status).toBe("chargeback");
    const t2 = await paid();
    await t2.send("dispute.accepted", { dispute_id: "dp_2", payment_id: "pay_1" });
    expect(t2.licenseStatus()).toBe("revoked");
  });
  it("out-of-order delivery: a refund that arrives before its payment is retried, then applies", async () => {
    const t = setup();
    const refund = t.delivery("refund.succeeded", { refund_id: "re_1", payment_id: "pay_1", is_partial: false }, { id: "msg_refund" });
    await expect(svc.handleWebhook(t.ctx, refund.raw, refund.headers)).rejects.toMatchObject({ status: 500 }); // Dodo will retry
    t.api.payments.set("pay_1", payment("pay_1"));
    await t.send("payment.succeeded", payment("pay_1"));
    expect((await svc.handleWebhook(t.ctx, refund.raw, refund.headers)).status).toBe("processed");
    expect(t.licenseStatus()).toBe("revoked");
  });
});

describe("Dodo persistence and configuration", () => {
  it("purchase and license records survive a restart", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tm-dodo-"));
    const file = path.join(dir, "lic.sqlite");
    const t = setup(file);
    t.api.payments.set("pay_1", payment("pay_1"));
    await t.send("payment.succeeded", payment("pay_1"));
    t.ctx.db.close();
    const db2 = openDb(file);
    expect((db2.prepare("SELECT COUNT(*) c FROM purchases WHERE provider = 'dodo'").get() as any).c).toBe(1);
    expect((db2.prepare("SELECT status FROM licenses").get() as any).status).toBe("active");
    db2.close();
    fs.rmSync(dir, { recursive: true });
  });
  const good = (): Record<string, string> => ({
    APP_ENV: "staging", PAYMENT_PROVIDER: "dodo", DODO_PAYMENTS_ENVIRONMENT: "test_mode", DODO_PAYMENTS_API_KEY: "k", DODO_PAYMENTS_WEBHOOK_SECRET: SECRET, DODO_PAYMENTS_PRODUCT_ID: PRODUCT,
    EMAIL_PROVIDER: "resend", EMAIL_FROM: "T <t@example.com>", RESEND_API_KEY: "r", WEBSITE_URL: "https://site.example", LICENSE_API_URL: "https://api.example", DATABASE_PATH: "/var/data/x.sqlite",
    LICENSE_SIGNING_PRIVATE_KEY: makeCtx().cfg.signing.privateKeyB64, CODE_HMAC_SECRET: "c".repeat(40), LICENSE_KEY_SECRET: "k".repeat(40), ALLOWED_ORIGINS: "https://site.example",
    IDENTITY_PROVIDER: "google", GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "s",
  });
  const problems = (e: Record<string, string>) => { try { loadConfig(e); } catch (x) { return (x as any).problems.join("\n"); } return ""; };
  it("staging uses test_mode and never produces live entitlements; production needs live_mode", () => {
    const c = loadConfig(good());
    expect(c.provider).toMatchObject({ name: "dodo", mode: "sandbox" });
    expect(c.entitlementMode).toBe("test");
    expect(c.provider.dodo.returnUrl).toBe("https://site.example/purchase-success/");
    expect(problems({ ...good(), DODO_PAYMENTS_ENVIRONMENT: "live_mode" })).toContain("test_mode");
    expect(problems({ ...good(), APP_ENV: "production" })).toContain("live_mode");
    const live = loadConfig({ ...good(), APP_ENV: "production", DODO_PAYMENTS_ENVIRONMENT: "live_mode" });
    expect(live.entitlementMode).toBe("live");
  });
  it("refuses to start with any Dodo setting missing", () => {
    for (const k of ["DODO_PAYMENTS_API_KEY", "DODO_PAYMENTS_WEBHOOK_SECRET", "DODO_PAYMENTS_PRODUCT_ID"]) {
      const e = good(); delete e[k];
      expect(problems(e), k).toContain(k);
    }
    expect(problems({ ...good(), DODO_PAYMENTS_RETURN_URL: "http://insecure.example/" })).toContain("https");
  });
});
