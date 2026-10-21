// @vitest-environment node
import { describe, expect, it } from "vitest";
import { ApiError } from "../src/errors.ts";
import * as svc from "../src/service.ts";
import { INST, lastCode, lastKey, makeCtx, payload } from "./helpers.ts";

type H = ReturnType<typeof makeCtx>;
const fail = (fn: () => unknown) => { try { fn(); } catch (e) { return e as ApiError; } throw new Error("expected failure"); };
const failAsync = async (p: Promise<unknown>) => { try { await p; } catch (e) { return e as ApiError; } throw new Error("expected failure"); };
const count = (h: H, table: string) => (h.ctx.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as any).n as number;

async function buy(h: H, email = "buyer@example.com", ids = { e: "evt_1", o: "txn_1" }, checkoutId?: string) {
  const f = h.provider.fixture("completed", { eventId: ids.e, orderId: ids.o, email, checkoutId, ts: h.clock.t, priceId: "pri_mock_tidymac_pro" });
  return svc.handleWebhook(h.ctx, f.raw, f.headers);
}
async function signIn(h: H, email: string, inst: string, ip = "ip1") {
  await svc.requestCode(h.ctx, { email, installationId: inst, ip });
  return svc.verifyCodeAndResolve(h.ctx, { email, code: lastCode(h.mail, email), installationId: inst, deviceName: "Mac", ip });
}

describe("verified purchases", () => {
  it("a signed webhook issues exactly one license and emails the key", async () => {
    const h = makeCtx();
    expect(await buy(h)).toEqual({ status: "processed" });
    expect(count(h, "licenses")).toBe(1);
    expect(lastKey(h.mail)).toMatch(/^TM-/);
    expect(h.mail.outbox.at(-1)!.subject).toContain("[TEST MODE]");
    expect((h.ctx.db.prepare("SELECT simulated FROM licenses").get() as any).simulated).toBe(1);
  });

  it("duplicate delivery of the same event is idempotent", async () => {
    const h = makeCtx();
    await buy(h);
    expect(await buy(h)).toEqual({ status: "duplicate" });
    expect(count(h, "licenses")).toBe(1);
    expect(count(h, "purchases")).toBe(1);
    expect(h.mail.outbox.filter((m) => /license/i.test(m.subject)).length).toBe(1);
  });

  it("a new event for the same order does not create a second license", async () => {
    const h = makeCtx();
    await buy(h, "buyer@example.com", { e: "evt_1", o: "txn_1" });
    await buy(h, "buyer@example.com", { e: "evt_2", o: "txn_1" });
    expect(count(h, "licenses")).toBe(1);
  });

  it("invalid, missing, stale and malformed signatures never grant anything", async () => {
    const h = makeCtx();
    const f = h.provider.fixture("completed", { eventId: "evt_x", orderId: "txn_x", email: "a@example.com", ts: h.clock.t, priceId: "pri_mock_tidymac_pro" });
    expect((await failAsync(svc.handleWebhook(h.ctx, f.raw + " ", f.headers))).status).toBe(401); // body altered
    expect((await failAsync(svc.handleWebhook(h.ctx, f.raw, {}))).code).toBe("invalid_signature");
    expect((await failAsync(svc.handleWebhook(h.ctx, f.raw, { "paddle-signature": "garbage" }))).code).toBe("invalid_signature");
    const stale = h.provider.fixture("completed", { eventId: "evt_y", orderId: "txn_y", email: "a@example.com", ts: h.clock.t - 10_000, priceId: "pri_mock_tidymac_pro" });
    expect((await failAsync(svc.handleWebhook(h.ctx, stale.raw, stale.headers))).code).toBe("invalid_signature");
    expect(count(h, "licenses")).toBe(0);
    expect(count(h, "purchases")).toBe(0);
    expect(count(h, "webhook_events")).toBe(0);
  });

  it("a purchase of a different price/product does not issue a license", async () => {
    const h = makeCtx();
    const f = h.provider.fixture("completed", { eventId: "evt_p", orderId: "txn_p", email: "a@example.com", ts: h.clock.t, priceId: "pri_other" });
    expect(await svc.handleWebhook(h.ctx, f.raw, f.headers)).toEqual({ status: "ignored" });
    expect(count(h, "licenses")).toBe(0);
  });

  it("the checkout redirect / success page alone proves nothing", async () => {
    const h = makeCtx();
    const c = await svc.createCheckout(h.ctx, { email: "buyer@example.com", ip: "ip" });
    expect(c.test_mode).toBe(true);
    expect(c.url).toContain("/dev/mock-checkout");
    expect(svc.checkoutStatus(h.ctx, c.checkout_id)).toEqual({ status: "pending" });
    expect(count(h, "licenses")).toBe(0);
    expect(fail(() => svc.activateWithKey(h.ctx, { licenseKey: "TM-AAAAA-BBBBB-CCCCC-DDDDD", installationId: INST(1), deviceName: "m", ip: "ip" })).code).toBe("invalid_key");
    await buy(h, "buyer@example.com", { e: "evt_c", o: "txn_c" }, c.checkout_id);
    expect(svc.checkoutStatus(h.ctx, c.checkout_id)).toEqual({ status: "confirmed" });
    expect(svc.checkoutStatus(h.ctx, "chk_unknown")).toEqual({ status: "unknown" });
  });

  it("refund and chargeback revoke; partial refunds do not", async () => {
    const h = makeCtx();
    await buy(h);
    const part = h.provider.fixture("refund_partial", { eventId: "evt_r0", orderId: "txn_1", ts: h.clock.t });
    expect(await svc.handleWebhook(h.ctx, part.raw, part.headers)).toEqual({ status: "ignored" });
    expect((h.ctx.db.prepare("SELECT status FROM licenses").get() as any).status).toBe("active");
    const full = h.provider.fixture("refund_full", { eventId: "evt_r1", orderId: "txn_1", ts: h.clock.t });
    expect(await svc.handleWebhook(h.ctx, full.raw, full.headers)).toEqual({ status: "processed" });
    expect((h.ctx.db.prepare("SELECT status, revoke_reason FROM licenses").get() as any)).toMatchObject({ status: "revoked", revoke_reason: "refunded" });
    const g = makeCtx();
    await buy(g);
    const cb = g.provider.fixture("chargeback", { eventId: "evt_c1", orderId: "txn_1", ts: g.clock.t });
    await svc.handleWebhook(g.ctx, cb.raw, cb.headers);
    expect((g.ctx.db.prepare("SELECT revoke_reason FROM licenses").get() as any).revoke_reason).toBe("chargeback");
  });

  it("a refund that arrives before its purchase fails (so the provider retries) and succeeds once the purchase exists", async () => {
    const h = makeCtx();
    const refund = h.provider.fixture("refund_full", { eventId: "evt_early", orderId: "txn_1", ts: h.clock.t });
    expect((await failAsync(svc.handleWebhook(h.ctx, refund.raw, refund.headers))).status).toBe(500);
    await buy(h);
    expect(await svc.handleWebhook(h.ctx, refund.raw, refund.headers)).toEqual({ status: "processed" });
    expect((h.ctx.db.prepare("SELECT status FROM licenses").get() as any).status).toBe("revoked");
  });
});

describe("licenses, devices and recovery", () => {
  it("activating with the emailed key issues a perpetual Pro entitlement (no expiry)", async () => {
    const h = makeCtx();
    await buy(h);
    const key = lastKey(h.mail);
    const r = svc.activateWithKey(h.ctx, { licenseKey: key.toLowerCase().replace(/-/g, " "), installationId: INST(1), deviceName: "Work Mac", ip: "ip" });
    const p = payload(h.pub, r.token);
    expect(p.kind).toBe("pro");
    expect(p.expires_at).toBeNull();
    expect(p.check_by).toBe(h.clock.t + 30 * 86400);
    expect(p.license).toBeTruthy();
  });

  it("a verified buyer who signs in gets Pro, not a trial", async () => {
    const h = makeCtx();
    await buy(h, "buyer@example.com");
    const r = await signIn(h, "buyer@example.com", INST(1));
    expect(r.kind).toBe("pro");
    expect(count(h, "trials")).toBe(0);
  });

  it("one Mac per license; the second is refused until one is released", async () => {
    const h = makeCtx();
    await buy(h);
    const key = lastKey(h.mail);
    svc.activateWithKey(h.ctx, { licenseKey: key, installationId: INST(1), deviceName: "A", ip: "ip" });
    svc.activateWithKey(h.ctx, { licenseKey: key, installationId: INST(1), deviceName: "A", ip: "ip" }); // same Mac again: not a new device
    const e = fail(() => svc.activateWithKey(h.ctx, { licenseKey: key, installationId: INST(2), deviceName: "B", ip: "ip" }));
    expect(e.code).toBe("device_limit");
    const r = svc.releaseAndActivate(h.ctx, { manageToken: e.extra.manage_token, deviceId: (e.extra.devices as any[])[0].id, installationId: INST(2), deviceName: "B" });
    expect(r.kind).toBe("pro");
    expect(count(h, "activations")).toBe(2);
    expect((h.ctx.db.prepare("SELECT COUNT(*) AS n FROM activations WHERE active = 1").get() as any).n).toBe(1);
  });

  it("deactivating this Mac frees a slot and invalidates that Mac's refresh", async () => {
    const h = makeCtx();
    await buy(h);
    const key = lastKey(h.mail);
    const a = svc.activateWithKey(h.ctx, { licenseKey: key, installationId: INST(1), deviceName: "A", ip: "ip" });
    svc.deactivate(h.ctx, { token: a.token, installationId: INST(1) });
    expect(fail(() => svc.refresh(h.ctx, { token: a.token, installationId: INST(1) })).code).toBe("device_deactivated");
    svc.activateWithKey(h.ctx, { licenseKey: key, installationId: INST(2), deviceName: "B", ip: "ip" });
    // B is active, so bringing A back would be a second active Mac
    expect(fail(() => svc.activateWithKey(h.ctx, { licenseKey: key, installationId: INST(1), deviceName: "A", ip: "ip" })).code).toBe("device_limit");
  });

  it("refresh renews a Pro token, and a refunded license is refused on its next refresh", async () => {
    const h = makeCtx();
    await buy(h);
    const a = svc.activateWithKey(h.ctx, { licenseKey: lastKey(h.mail), installationId: INST(1), deviceName: "A", ip: "ip" });
    h.clock.t += 10 * 86400;
    const r = svc.refresh(h.ctx, { token: a.token, installationId: INST(1) });
    expect(payload(h.pub, r.token).check_by).toBe(h.clock.t + 30 * 86400);
    const full = h.provider.fixture("refund_full", { eventId: "evt_rf", orderId: "txn_1", ts: h.clock.t });
    await svc.handleWebhook(h.ctx, full.raw, full.headers);
    const e = fail(() => svc.refresh(h.ctx, { token: r.token, installationId: INST(1) }));
    expect(e.code).toBe("revoked");
    expect(fail(() => svc.activateWithKey(h.ctx, { licenseKey: lastKey(h.mail), installationId: INST(9), deviceName: "x", ip: "ip" })).code).toBe("revoked");
  });

  it("a token cannot be used from another installation or forged", async () => {
    const h = makeCtx();
    const t = await signIn(h, "a@example.com", INST(1));
    expect(fail(() => svc.refresh(h.ctx, { token: t.token, installationId: INST(2) })).code).toBe("invalid_token");
    expect(fail(() => svc.refresh(h.ctx, { token: t.token.slice(0, -4) + "AAAA", installationId: INST(1) })).code).toBe("invalid_token");
    expect(fail(() => svc.listDevices(h.ctx, { token: "nonsense", installationId: INST(1) })).code).toBe("invalid_token");
    expect(svc.listDevices(h.ctx, { token: t.token, installationId: INST(1) }).devices[0]).toMatchObject({ this_device: true });
  });

  it("web recovery emails the key to a verified owner, never displays it, and reveals nothing about strangers", async () => {
    const h = makeCtx();
    await buy(h, "buyer@example.com");
    h.mail.outbox.length = 0;
    await svc.requestCode(h.ctx, { email: "buyer@example.com", installationId: "web", ip: "ip", purpose: "web_recover" });
    const res = await svc.recoverVerify(h.ctx, { email: "buyer@example.com", code: lastCode(h.mail), ip: "ip" });
    expect(JSON.stringify(res)).not.toMatch(/TM-/);
    expect(lastKey(h.mail)).toMatch(/^TM-/);
    // a stranger with a valid code gets the identical response and no email with a key
    await svc.requestCode(h.ctx, { email: "stranger@example.com", installationId: "web", ip: "ip2", purpose: "web_recover" });
    const before = h.mail.outbox.length;
    const res2 = await svc.recoverVerify(h.ctx, { email: "stranger@example.com", code: lastCode(h.mail), ip: "ip2" });
    expect(res2).toEqual(res);
    expect(h.mail.outbox.length).toBe(before);
    expect(count(h, "trials")).toBe(0); // recovery never creates a trial
  });
});

describe("persistence", () => {
  it("trials, purchases and licenses survive a server restart", async () => {
    const { mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const path = `${mkdtempSync(`${tmpdir()}/tidy-`)}/lic.sqlite`;
    const a = makeCtx({}, path);
    const first = payload(a.pub, (await signIn(a, "a@example.com", INST(1))).token);
    await buy(a);
    a.ctx.db.close();
    const { openDb } = await import("../src/db.ts");
    const db2 = openDb(path);
    expect((db2.prepare("SELECT expires_at FROM trials").get() as any).expires_at).toBe(first.expires_at);
    expect((db2.prepare("SELECT COUNT(*) AS n FROM licenses").get() as any).n).toBe(1);
    expect((db2.prepare("SELECT MAX(version) AS v FROM schema_migrations").get() as any).v).toBe(2);
    db2.close();
  });
});
