// @vitest-environment node
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { createAppServer } from "../src/app.ts";
import { PaddleProvider } from "../src/providers/paddle.ts";
import { signWebhookBody } from "../src/providers/signing.ts";
import { lastCode, makeCtx } from "./helpers.ts";

describe("HTTP API", () => {
  const h = makeCtx({ ALLOWED_ORIGINS: "https://site.example" });
  const server = createAppServer({ ...h.ctx, now: () => Math.floor(Date.now() / 1000) });
  let base = "";
  beforeAll(async () => { await new Promise<void>((r) => server.listen(0, "127.0.0.1", r)); base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; });
  afterAll(() => { server.close(); });
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) => fetch(base + path, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });

  it("health reveals nothing sensitive", async () => {
    const r = await fetch(`${base}/health`);
    expect(await r.json()).toEqual({ ok: true });
  });

  it("full trial activation over HTTP, and a verifiable signed token comes back", async () => {
    const inst = "install-http-0001";
    expect((await post("/v1/auth/request-code", { email: "web@example.com", installation_id: inst })).status).toBe(200);
    const bad = await post("/v1/auth/verify", { email: "web@example.com", code: "123456", installation_id: inst, device_name: "Mac" });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as any).error.code).toBe("invalid_code");
    const ok = await post("/v1/auth/verify", { email: "web@example.com", code: lastCode(h.mail, "web@example.com"), installation_id: inst, device_name: "Mac" });
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as any;
    expect(body.kind).toBe("trial");
    expect(body.token.startsWith("TM1.")).toBe(true);
    expect(JSON.stringify(body)).not.toContain("web@example.com"); // only a masked address is returned
  });

  it("rate-limit responses carry Retry-After", async () => {
    const r = await post("/v1/auth/request-code", { email: "web@example.com", installation_id: "install-http-0001" });
    expect(r.status).toBe(429);
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("CORS only for allowed origins", async () => {
    const ok = await fetch(`${base}/v1/checkout/status?checkout_id=x`, { headers: { Origin: "https://site.example" } });
    expect(ok.headers.get("access-control-allow-origin")).toBe("https://site.example");
    const no = await fetch(`${base}/v1/checkout/status?checkout_id=x`, { headers: { Origin: "https://evil.example" } });
    expect(no.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("unknown routes, bad JSON and oversized bodies are handled", async () => {
    expect((await fetch(`${base}/nope`)).status).toBe(404);
    const badJson = await fetch(`${base}/v1/auth/verify`, { method: "POST", body: "{not json" });
    expect(badJson.status).toBe(400);
    const big = await fetch(`${base}/v1/auth/verify`, { method: "POST", body: "x".repeat(300_000) }).catch(() => null);
    expect(big === null || big.status === 413).toBe(true);
  });

  it("the webhook endpoint needs a valid signature over the raw body", async () => {
    const f = h.provider.fixture("completed", { eventId: "evt_http", orderId: "txn_http", email: "http@example.com", ts: Math.floor(Date.now() / 1000), priceId: "pri_mock_tidymac_pro" });
    expect((await fetch(`${base}/v1/webhooks/mock`, { method: "POST", body: f.raw })).status).toBe(401);
    expect((await fetch(`${base}/v1/webhooks/mock`, { method: "POST", body: f.raw, headers: f.headers })).status).toBe(200);
    expect((await fetch(`${base}/v1/webhooks/paddle`, { method: "POST", body: f.raw, headers: f.headers })).status).toBe(404); // wrong provider path
    expect((h.ctx.db.prepare("SELECT COUNT(*) AS n FROM licenses").get() as any).n).toBe(1);
  });

  it("the simulated checkout page exists in development/test and is NOT served when the provider is Paddle", async () => {
    expect((await fetch(`${base}/dev/mock-checkout?checkout_id=chk_x`)).status).toBe(200);
    const real = makeCtx({ ALLOWED_ORIGINS: "https://site.example" });
    const prod = createAppServer({ ...real.ctx, provider: new PaddleProvider({ apiKey: "k", webhookSecret: "s", priceId: "pri_mock_tidymac_pro", mode: "sandbox", toleranceSec: 300 }) });
    await new Promise<void>((r) => prod.listen(0, "127.0.0.1", r));
    const b2 = `http://127.0.0.1:${(prod.address() as AddressInfo).port}`;
    expect((await fetch(`${b2}/dev/mock-checkout?checkout_id=chk_x`)).status).toBe(404);
    expect((await fetch(`${b2}/dev/mock-checkout/complete`, { method: "POST", body: "outcome=pay" })).status).toBe(404);
    const raw = JSON.stringify({ event_id: "evt_1", event_type: "transaction.completed", data: { id: "txn_1" } });
    const ts = Math.floor(Date.now() / 1000);
    const mockSig = h.provider.fixture("completed", { eventId: "x", orderId: "y", ts }).headers; // signed with the MOCK secret
    expect((await fetch(`${b2}/v1/webhooks/paddle`, { method: "POST", body: raw, headers: mockSig })).status).toBe(401);
    expect(signWebhookBody("s", ts, raw)).toHaveLength(64);
    prod.close();
  });
});
