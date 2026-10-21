import http from "node:http";
import { ApiError } from "./errors.ts";
import { sha256hex, randomId } from "./crypto.ts";
import { MockProvider } from "./providers/mock.ts";
import * as svc from "./service.ts";
import type { Ctx } from "./service.ts";

const MAX_BODY = 256 * 1024;

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > MAX_BODY) { reject(new ApiError(413, "too_large", "request too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export function createHandler(ctx: Ctx) {
  const devIdentity = ctx.identity.name === "mock" && (ctx.cfg.env === "development" || ctx.cfg.env === "test");
  const devMock = ctx.provider instanceof MockProvider && (ctx.cfg.env === "development" || ctx.cfg.env === "test");

  const send = (res: http.ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) => {
    const text = JSON.stringify(body);
    res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extra });
    res.end(text);
  };
  const html = (res: http.ServerResponse, status: number, body: string, extra: Record<string, string> = {}) => {
    res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...extra });
    res.end(body);
  };

  return async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const origin = req.headers.origin;
    const cors: Record<string, string> = {};
    if (origin && ctx.cfg.allowedOrigins.includes(origin)) {
      Object.assign(cors, { "Access-Control-Allow-Origin": origin, Vary: "Origin", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
    }
    const rawIp = ctx.cfg.trustProxy ? String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() || req.socket.remoteAddress : req.socket.remoteAddress;
    const ip = sha256hex(rawIp ?? "unknown").slice(0, 16);

    try {
      if (req.method === "OPTIONS") { res.writeHead(204, cors); res.end(); return; }
      if (req.method === "GET" && path === "/health") return send(res, 200, { ok: true }, cors);

      // ---- development-only simulated checkout (not registered in staging/production)
      if (devMock && path === "/dev/mock-checkout" && req.method === "GET") {
        const id = esc(url.searchParams.get("checkout_id") ?? "");
        const email = esc(url.searchParams.get("email") ?? "");
        return html(res, 200, `<!doctype html><meta charset=utf-8><title>TEST MODE checkout</title><body style="font:16px system-ui;max-width:460px;margin:60px auto"><div style="background:#fde68a;padding:12px;border-radius:8px"><b>TEST MODE.</b> This is a simulated checkout. No payment is taken and the license it creates is a test license.</div><h2>TidyMac Pro (simulated)</h2><form method=post action="/dev/mock-checkout/complete"><input type=hidden name=checkout_id value="${id}"><p><label>Email<br><input name=email value="${email}" type=email style="width:100%;padding:8px"></label></p><p><button name=outcome value=pay>Simulate successful payment</button> <button name=outcome value=cancel>Cancel</button> <button name=outcome value=fail>Simulate failure</button></p></form>`);
      }
      if (devMock && path === "/dev/mock-checkout/complete" && req.method === "POST") {
        const form = new URLSearchParams(await readBody(req));
        const checkoutId = form.get("checkout_id") ?? "";
        const outcome = form.get("outcome");
        const email = form.get("email") ?? "";
        const back = (p: string) => ({ Location: `${ctx.cfg.websiteUrl}${p}` });
        if (outcome === "pay") {
          const f = (ctx.provider as MockProvider).fixture("completed", { eventId: randomId("evt_mock"), orderId: randomId("txn_mock"), email, checkoutId, ts: ctx.now(), priceId: ctx.priceId });
          await svc.handleWebhook(ctx, f.raw, f.headers);
          res.writeHead(302, back(`/purchase-success/?checkout_id=${encodeURIComponent(checkoutId)}`)); res.end(); return;
        }
        ctx.db.prepare("UPDATE checkouts SET status = ?, updated_at = ? WHERE id = ?").run(outcome === "fail" ? "failed" : "canceled", ctx.now(), checkoutId);
        res.writeHead(302, back(`/pricing/?checkout=${outcome === "fail" ? "failed" : "canceled"}`)); res.end(); return;
      }

      // ---- Sign in with Google: browser legs (GET redirects) -----------------------------------------------------------------
      if (req.method === "GET" && path === "/v1/auth/google/begin") {
        try {
          res.writeHead(302, { Location: svc.beginProvider(ctx, url.searchParams.get("s")), "Cache-Control": "no-store" });
        } catch {
          res.writeHead(302, { Location: `${ctx.cfg.websiteUrl}/signin-failed/` });
        }
        res.end();
        return;
      }
      if (req.method === "GET" && path === "/v1/auth/google/callback") {
        const next = await svc.completeProvider(ctx, { state: url.searchParams.get("state"), code: url.searchParams.get("code"), error: url.searchParams.get("error") });
        res.writeHead(302, { Location: next, "Cache-Control": "no-store" });
        res.end();
        return;
      }
      if (devIdentity && path === "/dev/mock-signin" && req.method === "GET") {
        const st = esc(url.searchParams.get("state") ?? "");
        return html(res, 200, `<!doctype html><meta charset=utf-8><title>TEST MODE sign-in</title><body style="font:16px system-ui;max-width:460px;margin:60px auto"><div style="background:#fde68a;padding:12px;border-radius:8px"><b>TEST MODE.</b> This stands in for "Sign in with Google" during development. No real account is involved.</div><h2>Simulated Google sign-in</h2><form method=post action="/dev/mock-signin/complete"><input type=hidden name=state value="${st}"><p><label>Email to sign in as<br><input name=email type=email required style="width:100%;padding:8px"></label></p><p><button>Sign in</button> <button name=cancel value=1 formnovalidate>Cancel</button></p></form>`);
      }
      if (devIdentity && path === "/dev/mock-signin/complete" && req.method === "POST") {
        const form = new URLSearchParams(await readBody(req));
        const next = form.get("cancel") ? await svc.completeProvider(ctx, { state: form.get("state"), code: null, error: "access_denied" }) : await svc.completeMockSignin(ctx, form.get("state") ?? "", form.get("email") ?? "");
        res.writeHead(302, { Location: next });
        res.end();
        return;
      }

      // ---- webhooks: raw body, signature checked before anything else
      const wh = path.match(/^\/v1\/webhooks\/(\w+)$/);
      if (wh && req.method === "POST") {
        if (wh[1] !== ctx.provider.name) throw new ApiError(404, "not_found", "unknown provider");
        const raw = await readBody(req);
        const headers: Record<string, string | undefined> = {};
        for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v[0] : v;
        return send(res, 200, await svc.handleWebhook(ctx, raw, headers));
      }

      if (req.method === "GET" && path === "/v1/checkout/status") return send(res, 200, svc.checkoutStatus(ctx, url.searchParams.get("checkout_id")), cors);

      if (req.method === "POST" && path.startsWith("/v1/")) {
        const text = await readBody(req);
        let b: Record<string, unknown> = {};
        if (text) { try { b = JSON.parse(text); } catch { throw new ApiError(400, "invalid_body", "body must be JSON"); } }
        switch (path) {
          case "/v1/auth/request-code": return send(res, 200, await svc.requestCode(ctx, { email: b.email, installationId: b.installation_id, ip }), cors);
          case "/v1/auth/verify": return send(res, 200, svc.verifyCodeAndResolve(ctx, { email: b.email, code: b.code, installationId: b.installation_id, deviceName: b.device_name, ip }), cors);
          case "/v1/auth/oauth/start": return send(res, 200, svc.startWebSignin(ctx, { installationId: b.installation_id, codeChallenge: b.code_challenge, ip }), cors);
          case "/v1/auth/oauth/poll": { const r = svc.pollWebSignin(ctx, { sessionId: b.session_id, codeVerifier: b.code_verifier, installationId: b.installation_id, deviceName: b.device_name }); return send(res, r.status === "pending" ? 202 : 200, r, cors); }
          case "/v1/license/activate": return send(res, 200, svc.activateWithKey(ctx, { licenseKey: b.license_key, installationId: b.installation_id, deviceName: b.device_name, ip }), cors);
          case "/v1/entitlement/refresh": return send(res, 200, svc.refresh(ctx, { token: b.token, installationId: b.installation_id }), cors);
          case "/v1/devices/list": return send(res, 200, svc.listDevices(ctx, { token: b.token, installationId: b.installation_id }), cors);
          case "/v1/devices/deactivate": return send(res, 200, svc.deactivate(ctx, { token: b.token, installationId: b.installation_id }), cors);
          case "/v1/devices/release": return send(res, 200, svc.releaseAndActivate(ctx, { manageToken: b.manage_token, deviceId: b.device_id, installationId: b.installation_id, deviceName: b.device_name }), cors);
          case "/v1/recover/request": return send(res, 200, await svc.requestCode(ctx, { email: b.email, installationId: "web", ip, purpose: "web_recover" }), cors);
          case "/v1/recover/verify": return send(res, 200, await svc.recoverVerify(ctx, { email: b.email, code: b.code, ip }), cors);
          case "/v1/checkout": return send(res, 200, await svc.createCheckout(ctx, { email: b.email, ip }), cors);
        }
      }
      throw new ApiError(404, "not_found", "not found");
    } catch (e) {
      if (e instanceof ApiError) {
        const headers = { ...cors, ...(e.extra.retry_after ? { "Retry-After": String(e.extra.retry_after) } : {}) };
        return send(res, e.status, { error: { code: e.code, message: e.message, ...e.extra } }, headers);
      }
      console.error("unhandled error:", (e as Error).message); // never log request bodies, codes or tokens
      return send(res, 500, { error: { code: "internal", message: "Something went wrong." } }, cors);
    }
  };
}

export function createAppServer(ctx: Ctx) {
  return http.createServer((req, res) => void createHandler(ctx)(req, res));
}
