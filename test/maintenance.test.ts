// @vitest-environment node
import { describe, expect, it } from "vitest";
import { prune } from "../src/maintenance.ts";
import * as svc from "../src/service.ts";
import { lastCode, makeCtx } from "./helpers.ts";

describe("retention", () => {
  it("deletes old codes, tokens, audit and rate rows but keeps customers, trials, licenses and purchases", async () => {
    const h = makeCtx();
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: "install-00000001", ip: "ip" });
    svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: lastCode(h.mail), installationId: "install-00000001", deviceName: "m", ip: "ip" });
    const f = h.provider.fixture("completed", { eventId: "evt_1", orderId: "txn_1", email: "a@example.com", ts: h.clock.t, priceId: "pri_mock_tidymac_pro" });
    await svc.handleWebhook(h.ctx, f.raw, f.headers);
    const count = (t: string) => (h.ctx.db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get() as any).n as number;
    const before = { customers: count("customers"), trials: count("trials"), licenses: count("licenses"), purchases: count("purchases") };
    expect(prune(h.ctx.db, h.clock.t + 3600)).toMatchObject({ codes: 0, audit: 0 }); // too recent
    const r = prune(h.ctx.db, h.clock.t + 401 * 86400);
    expect(r.codes).toBeGreaterThan(0);
    expect(r.audit).toBeGreaterThan(0);
    expect(count("email_codes")).toBe(0);
    expect({ customers: count("customers"), trials: count("trials"), licenses: count("licenses"), purchases: count("purchases") }).toEqual(before);
  });
});
