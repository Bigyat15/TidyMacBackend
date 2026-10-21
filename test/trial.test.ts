// @vitest-environment node
import { describe, expect, it } from "vitest";
import { ApiError } from "../src/errors.ts";
import * as svc from "../src/service.ts";
import { signEntitlement, verifyEntitlement } from "../src/crypto.ts";
import { INST, lastCode, makeCtx, payload } from "./helpers.ts";

async function signIn(h: ReturnType<typeof makeCtx>, email: string, inst: string, ip = "ip1") {
  await svc.requestCode(h.ctx, { email, installationId: inst, ip });
  return svc.verifyCodeAndResolve(h.ctx, { email, code: lastCode(h.mail, email), installationId: inst, deviceName: "My Mac", ip });
}
const fail = (fn: () => unknown) => { try { fn(); } catch (e) { return e as ApiError; } throw new Error("expected failure"); };
const failAsync = async (p: Promise<unknown>) => { try { await p; } catch (e) { return e as ApiError; } throw new Error("expected failure"); };

describe("trial", () => {
  it("starts on verified activation and lasts exactly 24 elapsed hours", async () => {
    const h = makeCtx();
    const r = await signIn(h, "a@example.com", INST(1));
    expect(r.kind).toBe("trial");
    const p = payload(h.pub, r.token);
    expect(p.expires_at).toBe(h.clock.t + 24 * 3600);
    expect(p.installation).toBe(INST(1));
    expect(p.product).toBe("tidymac");
    expect(p.mode).toBe("test"); // mock provider => test entitlements
    expect(r.trial_expired).toBe(false);
  });

  it("a verified customer gets ONE trial: reinstall, new installation id and later sign-ins never restart it", async () => {
    const h = makeCtx();
    const first = payload(h.pub, (await signIn(h, "a@example.com", INST(1))).token);
    h.clock.t += 5 * 3600;
    // "reinstall": different installation id, no local state -> triggers device_limit on 1-Mac policy, then released
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(2), ip: "ip1" });
    const e = fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: lastCode(h.mail), installationId: INST(2), deviceName: "Reinstalled Mac", ip: "ip1" }));
    expect(e.code).toBe("device_limit");
    const again = svc.releaseAndActivate(h.ctx, { manageToken: e.extra.manage_token, deviceId: (e.extra.devices as any[])[0].id, installationId: INST(2), deviceName: "Reinstalled Mac" });
    expect(payload(h.pub, again.token).expires_at).toBe(first.expires_at);
    h.clock.t += 20 * 3600; // past expiry
    const late = await signIn(h, "a@example.com", INST(2)); // the registered Mac
    expect(late.trial_expired).toBe(true);
    expect(payload(h.pub, late.token).expires_at).toBe(first.expires_at);
    expect((h.ctx.db.prepare("SELECT COUNT(*) AS n FROM trials").get() as any).n).toBe(1);
  });

  it("email case and whitespace do not create a second customer", async () => {
    const h = makeCtx();
    await signIn(h, "Person@Example.com", INST(1));
    h.clock.t += 60;
    await signIn(h, "  person@example.COM ", INST(1));
    expect((h.ctx.db.prepare("SELECT COUNT(*) AS n FROM trials").get() as any).n).toBe(1);
  });

  it("an expired trial token is still signed but reports its past expiry (client derives read-only mode)", async () => {
    const h = makeCtx();
    const r = await signIn(h, "a@example.com", INST(1));
    h.clock.t += 25 * 3600;
    const ref = svc.refresh(h.ctx, { token: r.token, installationId: INST(1) });
    const p = payload(h.pub, ref.token);
    expect(p.expires_at! < h.clock.t).toBe(true);
    expect(p.expires_at).toBe(payload(h.pub, r.token).expires_at);
  });

  it("limits a trial to one Mac and lets the user free one", async () => {
    const h = makeCtx();
    await signIn(h, "a@example.com", INST(1));
    h.clock.t += 60;
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(2), ip: "ip1" });
    const e = fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: lastCode(h.mail), installationId: INST(2), deviceName: "Second", ip: "ip1" }));
    expect(e.code).toBe("device_limit");
    expect((e.extra.devices as any[]).length).toBe(1);
    const dev = (e.extra.devices as any[])[0];
    const r = svc.releaseAndActivate(h.ctx, { manageToken: e.extra.manage_token, deviceId: dev.id, installationId: INST(2), deviceName: "Second" });
    expect(r.kind).toBe("trial");
    // the token is single use
    expect(fail(() => svc.releaseAndActivate(h.ctx, { manageToken: e.extra.manage_token, deviceId: dev.id, installationId: INST(3), deviceName: "x" })).code).toBe("invalid_token");
  });

  it("entitlement tokens: tampering, wrong key and foreign products are rejected", async () => {
    const h = makeCtx();
    const r = await signIn(h, "a@example.com", INST(1));
    const [pre, body, sig] = r.token.split(".");
    const tampered = JSON.parse(Buffer.from(body, "base64url").toString());
    tampered.expires_at += 999999;
    expect(verifyEntitlement(h.pub, `${pre}.${Buffer.from(JSON.stringify(tampered)).toString("base64url")}.${sig}`)).toBeNull();
    const other = makeCtx();
    expect(verifyEntitlement(other.pub, r.token)).toBeNull();
    const forged = signEntitlement(h.cfg.signing.privateKeyB64, { ...payload(h.pub, r.token), product: "other" as any });
    expect(verifyEntitlement(h.pub, forged)).toBeNull();
    expect(verifyEntitlement(h.pub, "TM2.a.b")).toBeNull();
  });
});

describe("email codes and abuse controls", () => {
  it("a wrong code is rejected, and five wrong attempts lock the code", async () => {
    const h = makeCtx();
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: "ip" });
    const good = lastCode(h.mail);
    const wrong = good === "000000" ? "111111" : "000000";
    for (let i = 0; i < 4; i++) expect(fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: wrong, installationId: INST(1), deviceName: "m", ip: "ip" })).code).toBe("invalid_code");
    expect(fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: wrong, installationId: INST(1), deviceName: "m", ip: "ip" })).code).toBe("too_many_attempts");
    // even the right code no longer works
    expect(fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: good, installationId: INST(1), deviceName: "m", ip: "ip" })).code).toBe("invalid_code");
  });

  it("codes expire after 10 minutes and cannot be reused", async () => {
    const h = makeCtx();
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: "ip" });
    const code = lastCode(h.mail);
    h.clock.t += 601;
    expect(fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code, installationId: INST(1), deviceName: "m", ip: "ip" })).code).toBe("code_expired");
    h.clock.t += 60;
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: "ip" });
    const c2 = lastCode(h.mail);
    svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: c2, installationId: INST(1), deviceName: "m", ip: "ip" });
    expect(fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: c2, installationId: INST(2), deviceName: "m", ip: "ip" })).code).toBe("invalid_code");
  });

  it("a newer code supersedes the older one", async () => {
    const h = makeCtx();
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: "ip" });
    const old = lastCode(h.mail);
    h.clock.t += 31;
    await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: "ip" });
    const fresh = lastCode(h.mail);
    if (old !== fresh) expect(fail(() => svc.verifyCodeAndResolve(h.ctx, { email: "a@example.com", code: old, installationId: INST(1), deviceName: "m", ip: "ip" })).code).toBe("invalid_code");
  });

  it("rate limits code requests per email, per IP and per installation, and enforces a cooldown", async () => {
    const h = makeCtx();
    expect((await failAsync(svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: "ip" }).then(() => svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: "ip" })))).code).toBe("too_soon");
    for (let i = 0; i < 4; i++) { h.clock.t += 31; await svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(1), ip: `ip${i}` }); }
    h.clock.t += 31;
    const e = await failAsync(svc.requestCode(h.ctx, { email: "a@example.com", installationId: INST(9), ip: "ipX" }));
    expect(e.code).toBe("rate_limited");
    expect(e.extra.retry_after).toBeGreaterThan(0);
    // per-IP limit across many emails
    const g = makeCtx();
    for (let i = 0; i < 20; i++) await svc.requestCode(g.ctx, { email: `u${i}@example.com`, installationId: INST(100 + i), ip: "same" });
    expect((await failAsync(svc.requestCode(g.ctx, { email: "u99@example.com", installationId: INST(999), ip: "same" }))).code).toBe("rate_limited");
  });

  it("validates input and never reveals whether an address already exists", async () => {
    const h = makeCtx();
    expect((await failAsync(svc.requestCode(h.ctx, { email: "not-an-email", installationId: INST(1), ip: "ip" }))).code).toBe("invalid_email");
    expect((await failAsync(svc.requestCode(h.ctx, { email: "a@example.com", installationId: "x", ip: "ip" }))).code).toBe("invalid_installation");
    const fresh = await svc.requestCode(h.ctx, { email: "new@example.com", installationId: INST(1), ip: "ip" });
    await signIn(h, "old@example.com", INST(2), "ip2");
    h.clock.t += 31;
    const known = await svc.requestCode(h.ctx, { email: "old@example.com", installationId: INST(3), ip: "ip3" });
    expect(known).toEqual(fresh);
  });

  it("never stores codes or full emails in the audit log", async () => {
    const h = makeCtx();
    await signIn(h, "secret.person@example.com", INST(1));
    const rows = JSON.stringify(h.ctx.db.prepare("SELECT * FROM audit_events").all());
    expect(rows).not.toContain("secret.person");
    expect(rows).not.toContain(lastCode(h.mail));
  });
});
