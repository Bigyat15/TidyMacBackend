import type { Config } from "./config.ts";
import { type Db, tx } from "./db.ts";
import {
  type EntitlementPayload, decryptSecret, encryptSecret, generateLicenseKey, hmacHex, normalizeLicenseKey, publicKeyOf, randomId,
  safeEqual, sha256hex, signEntitlement, verifyEntitlement,
} from "./crypto.ts";
import { ApiError } from "./errors.ts";
import { type Mailer, maskEmail } from "./mail.ts";
import { hit } from "./ratelimit.ts";
import crypto from "node:crypto";
import type { PaymentProvider } from "./providers/types.ts";
import type { IdentityProvider } from "./identity/types.ts";

export interface Ctx {
  cfg: Config;
  db: Db;
  mail: Mailer;
  provider: PaymentProvider;
  identity: IdentityProvider;
  /** The configured product price id; purchases for any other price never issue a license. */
  priceId: string;
  now: () => number;
}

type Row = Record<string, any>;
const get = (db: Db, sql: string, ...p: any[]) => db.prepare(sql).get(...p) as Row | undefined;
const all = (db: Db, sql: string, ...p: any[]) => db.prepare(sql).all(...p) as Row[];
const run = (db: Db, sql: string, ...p: any[]) => db.prepare(sql).run(...p);

export function audit(ctx: Ctx, type: string, customerId: string | null, meta: Record<string, unknown> = {}) {
  run(ctx.db, "INSERT INTO audit_events(ts, type, customer_id, meta) VALUES (?, ?, ?, ?)", ctx.now(), type, customerId, JSON.stringify(meta));
}

export function normalizeEmail(raw: unknown): string {
  const e = String(raw ?? "").trim().toLowerCase();
  if (e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) throw new ApiError(400, "invalid_email", "Enter a valid email address.");
  return e;
}
function checkInstallation(raw: unknown): string {
  const s = String(raw ?? "");
  if (!/^[A-Za-z0-9-]{8,64}$/.test(s)) throw new ApiError(400, "invalid_installation", "invalid installation id");
  return s;
}
const cleanDeviceName = (raw: unknown) => String(raw ?? "Mac").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 60) || "Mac";

function limited(ctx: Ctx, bucket: string, limit: number, windowSec = 3600) {
  const wait = hit(ctx.db, bucket, limit, windowSec, ctx.now());
  if (wait > 0) throw new ApiError(429, "rate_limited", "Too many attempts. Please wait and try again.", { retry_after: wait });
}

/** One person, one identity: Gmail ignores dots and "+tags", so they must not buy a second trial with an alias. */
export function canonicalEmail(e: string): string {
  const [local, domain] = e.split("@");
  return domain === "gmail.com" || domain === "googlemail.com" ? `${local.split("+")[0].replace(/\./g, "")}@gmail.com` : e;
}

/** Finds the customer for this (already normalized) email, or creates one. `verified` records proof of ownership. */
function findOrCreateCustomer(ctx: Ctx, email: string, verified: boolean): string {
  const canon = canonicalEmail(email);
  const c = get(ctx.db, "SELECT id FROM customers WHERE canon = ? OR email = ? ORDER BY created_at LIMIT 1", canon, email);
  if (c) {
    if (verified) run(ctx.db, "UPDATE customers SET email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?", ctx.now(), c.id);
    return c.id as string;
  }
  const id = randomId("cus");
  run(ctx.db, "INSERT INTO customers(id, email, canon, email_verified_at, created_at) VALUES (?, ?, ?, ?, ?)", id, email, canon, verified ? ctx.now() : null, ctx.now());
  return id;
}

const codeHmac = (ctx: Ctx, id: string, email: string, code: string) => hmacHex(ctx.cfg.secrets.codes, id, email, code);
const keyHmac = (ctx: Ctx, key: string) => hmacHex(ctx.cfg.secrets.licenseKeys, "license-key", key);

// ---------------------------------------------------------------- email codes

export async function requestCode(ctx: Ctx, i: { email: unknown; installationId: unknown; ip: string; purpose?: "signin" | "web_recover" }) {
  const email = normalizeEmail(i.email);
  const purpose = i.purpose ?? "signin";
  const inst = purpose === "signin" ? checkInstallation(i.installationId) : "web";
  const last = get(ctx.db, "SELECT created_at FROM email_codes WHERE email = ? AND purpose = ? ORDER BY created_at DESC LIMIT 1", email, purpose);
  if (last && ctx.now() - last.created_at < ctx.cfg.policy.codeCooldownSec) {
    throw new ApiError(429, "too_soon", "A code was just sent. Please wait a moment before requesting another.", { retry_after: ctx.cfg.policy.codeCooldownSec - (ctx.now() - last.created_at) });
  }
  const r = ctx.cfg.rate;
  limited(ctx, `code:email:${sha256hex(email)}`, r.codePerEmailHour);
  limited(ctx, `code:ip:${i.ip}`, r.codePerIpHour);
  if (purpose === "signin") limited(ctx, `code:inst:${inst}`, r.codePerInstallationHour);
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
  const id = randomId("cod");
  tx(ctx.db, () => {
    run(ctx.db, "UPDATE email_codes SET consumed_at = ? WHERE email = ? AND purpose = ? AND consumed_at IS NULL", ctx.now(), email, purpose);
    run(ctx.db, "INSERT INTO email_codes(id, email, purpose, code_hmac, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)", id, email, purpose, codeHmac(ctx, id, email, code), ctx.now() + ctx.cfg.policy.codeTtlSec, ctx.now());
  });
  await ctx.mail.send({
    to: email,
    subject: "Your TidyMac verification code",
    text: `Your TidyMac verification code is ${code}.\n\nIt expires in ${Math.round(ctx.cfg.policy.codeTtlSec / 60)} minutes. If you didn't request it, you can ignore this email.`,
  });
  audit(ctx, "code_requested", null, { email_hash: sha256hex(email).slice(0, 16), purpose });
  // The response never reveals whether the address already has a trial or a license.
  return { ok: true, expires_in: ctx.cfg.policy.codeTtlSec };
}

/** Consumes a correct code. Throws invalid_code / code_expired / too_many_attempts. */
function consumeCode(ctx: Ctx, email: string, code: string, purpose: string) {
  const row = get(ctx.db, "SELECT * FROM email_codes WHERE email = ? AND purpose = ? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1", email, purpose);
  if (!row) throw new ApiError(400, "invalid_code", "That code is not valid. Request a new one.");
  if (ctx.now() > row.expires_at) throw new ApiError(400, "code_expired", "That code has expired. Request a new one.");
  const attempts = row.attempts + 1;
  run(ctx.db, "UPDATE email_codes SET attempts = ? WHERE id = ?", attempts, row.id);
  const ok = /^\d{6}$/.test(code) && safeEqual(codeHmac(ctx, row.id, email, code), row.code_hmac);
  if (!ok) {
    if (attempts >= ctx.cfg.policy.codeMaxAttempts) {
      run(ctx.db, "UPDATE email_codes SET consumed_at = ? WHERE id = ?", ctx.now(), row.id);
      audit(ctx, "code_locked", null, { email_hash: sha256hex(email).slice(0, 16) });
      throw new ApiError(429, "too_many_attempts", "Too many wrong codes. Request a new code.");
    }
    throw new ApiError(400, "invalid_code", "That code is not valid.", { attempts_left: ctx.cfg.policy.codeMaxAttempts - attempts });
  }
  run(ctx.db, "UPDATE email_codes SET consumed_at = ? WHERE id = ?", ctx.now(), row.id);
}

// ---------------------------------------------------------------- entitlements

interface Owner { customerId: string; trialId?: string; licenseId?: string }

function issueToken(ctx: Ctx, o: { kind: "trial" | "pro"; owner: Owner; installation: string; activationId: string; expiresAt: number | null; startedAt?: number | null }) {
  const now = ctx.now();
  const payload: EntitlementPayload = {
    v: 1, product: "tidymac", kind: o.kind, mode: ctx.cfg.entitlementMode, ent_id: randomId("ent"), customer: o.owner.customerId,
    installation: o.installation, activation: o.activationId, license: o.owner.licenseId ?? null, issued_at: now, started_at: o.startedAt ?? null, expires_at: o.expiresAt,
    check_by: o.kind === "trial" ? (o.expiresAt as number) : now + ctx.cfg.policy.offlineGraceDays * 86400,
    updates_through_major: 1, kid: ctx.cfg.signing.kid,
  };
  const email = (get(ctx.db, "SELECT email FROM customers WHERE id = ?", o.owner.customerId) as Row).email as string;
  return {
    token: signEntitlement(ctx.cfg.signing.privateKeyB64, payload),
    kind: o.kind, mode: payload.mode, issued_at: now, expires_at: payload.expires_at, check_by: payload.check_by,
    email_masked: maskEmail(email),
  };
}

const ownerWhere = (o: Owner) => (o.trialId ? ["trial_id = ?", o.trialId] : ["license_id = ?", o.licenseId]) as [string, any];

function devicesOf(ctx: Ctx, o: Owner) {
  const [w, v] = ownerWhere(o);
  return all(ctx.db, `SELECT id, device_name AS name, created_at, last_seen_at FROM activations WHERE ${w} AND active = 1 ORDER BY created_at`, v);
}

/** Activates (or re-activates) one installation. Returns the devices instead when the limit is reached. Runs inside a transaction. */
function activate(ctx: Ctx, o: Owner, installation: string, deviceName: string, max: number): { id: string } | { full: Row[] } {
  const [w, v] = ownerWhere(o);
  const existing = get(ctx.db, `SELECT * FROM activations WHERE ${w} AND installation_id = ?`, v, installation);
  if (existing?.active) {
    run(ctx.db, "UPDATE activations SET last_seen_at = ?, device_name = ? WHERE id = ?", ctx.now(), deviceName, existing.id);
    return { id: existing.id };
  }
  if (devicesOf(ctx, o).length >= max) return { full: devicesOf(ctx, o) };
  if (existing) {
    run(ctx.db, "UPDATE activations SET active = 1, deactivated_at = NULL, last_seen_at = ?, device_name = ? WHERE id = ?", ctx.now(), deviceName, existing.id);
    return { id: existing.id };
  }
  const id = randomId("act");
  run(ctx.db, "INSERT INTO activations(id, trial_id, license_id, installation_id, device_name, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)", id, o.trialId ?? null, o.licenseId ?? null, installation, deviceName, ctx.now(), ctx.now());
  return { id };
}

function deviceLimit(ctx: Ctx, o: Owner, devices: Row[]): ApiError {
  const raw = crypto.randomBytes(24).toString("base64url");
  run(ctx.db, "INSERT INTO manage_tokens(id, token_hmac, customer_id, trial_id, license_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)", randomId("mtk"), hmacHex(ctx.cfg.secrets.codes, "manage", raw), o.customerId, o.trialId ?? null, o.licenseId ?? null, ctx.now() + 600);
  return new ApiError(409, "device_limit", `This license is already active on another Mac. Deactivate it to continue.`, { devices, manage_token: raw, max_devices: ctx.cfg.policy.maxDevices });
}

/** Best entitlement for a verified customer: a paid license if there is one, otherwise their (single) trial. */
function resolveForCustomer(ctx: Ctx, customerId: string, installation: string, deviceName: string) {
  let limitErr: ApiError | null = null;
  const result = tx(ctx.db, () => {
    const lic = get(ctx.db, "SELECT id, max_devices FROM licenses WHERE customer_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1", customerId);
    if (lic) {
      const owner: Owner = { customerId, licenseId: lic.id };
      const a = activate(ctx, owner, installation, deviceName, lic.max_devices);
      if ("full" in a) { limitErr = { owner, devices: a.full } as any; return null; }
      audit(ctx, "license_activated", customerId, { license: lic.id });
      return { ...issueToken(ctx, { kind: "pro", owner, installation, activationId: a.id, expiresAt: null }), license_id: lic.id as string, trial_expired: false, license_revoked: false };
    }
    const revoked = !!get(ctx.db, "SELECT 1 AS x FROM licenses WHERE customer_id = ? AND status = 'revoked' LIMIT 1", customerId);
    let trial = get(ctx.db, "SELECT * FROM trials WHERE customer_id = ?", customerId);
    if (!trial) {
      const id = randomId("trl");
      run(ctx.db, "INSERT INTO trials(id, customer_id, started_at, expires_at) VALUES (?, ?, ?, ?)", id, customerId, ctx.now(), ctx.now() + ctx.cfg.policy.trialHours * 3600);
      trial = get(ctx.db, "SELECT * FROM trials WHERE id = ?", id) as Row;
      audit(ctx, "trial_started", customerId, { trial: id });
    }
    const owner: Owner = { customerId, trialId: trial.id };
    const a = activate(ctx, owner, installation, deviceName, ctx.cfg.policy.maxDevices);
    if ("full" in a) { limitErr = { owner, devices: a.full } as any; return null; }
    return { ...issueToken(ctx, { kind: "trial", owner, installation, activationId: a.id, expiresAt: trial.expires_at, startedAt: trial.started_at }), trial_expired: ctx.now() >= trial.expires_at, license_revoked: revoked };
  });
  if (!result) {
    const { owner, devices } = limitErr as any;
    throw deviceLimit(ctx, owner, devices); // created outside the rolled-back transaction
  }
  return result;
}

export function verifyCodeAndResolve(ctx: Ctx, i: { email: unknown; code: unknown; installationId: unknown; deviceName: unknown; ip: string }) {
  const email = normalizeEmail(i.email);
  const inst = checkInstallation(i.installationId);
  limited(ctx, `verify:ip:${i.ip}`, ctx.cfg.rate.verifyPerIpHour);
  // Attempt counting must NOT run inside a transaction that rolls back on failure, or brute-force limits would be undone.
  consumeCode(ctx, email, String(i.code ?? ""), "signin");
  const customerId = tx(ctx.db, () => {
    return findOrCreateCustomer(ctx, email, true);
  });
  return resolveForCustomer(ctx, customerId, inst, cleanDeviceName(i.deviceName));
}

export function activateWithKey(ctx: Ctx, i: { licenseKey: unknown; installationId: unknown; deviceName: unknown; ip: string }) {
  limited(ctx, `key:ip:${i.ip}`, ctx.cfg.rate.keyAttemptsPerIpHour);
  const inst = checkInstallation(i.installationId);
  const key = normalizeLicenseKey(String(i.licenseKey ?? ""));
  const lic = key ? get(ctx.db, "SELECT * FROM licenses WHERE key_hmac = ?", keyHmac(ctx, key)) : undefined;
  if (!lic) throw new ApiError(404, "invalid_key", "That license key was not found. Check it and try again.");
  if (lic.status !== "active") throw new ApiError(403, "revoked", "This license is no longer active (refunded or revoked).");
  const owner: Owner = { customerId: lic.customer_id, licenseId: lic.id };
  let full: Row[] | null = null;
  const out = tx(ctx.db, () => {
    const a = activate(ctx, owner, inst, cleanDeviceName(i.deviceName), lic.max_devices);
    if ("full" in a) { full = a.full; return null; }
    audit(ctx, "license_activated", lic.customer_id, { license: lic.id, via: "key" });
    return { ...issueToken(ctx, { kind: "pro", owner, installation: inst, activationId: a.id, expiresAt: null }), license_id: lic.id as string, trial_expired: false, license_revoked: false };
  });
  if (!out) throw deviceLimit(ctx, owner, full!);
  return out;
}

function ownTokenPayload(ctx: Ctx, token: unknown, installationId: unknown): EntitlementPayload {
  const inst = checkInstallation(installationId);
  const p = verifyEntitlement(publicKeyOf(ctx.cfg.signing.privateKeyB64), String(token ?? ""));
  if (!p || p.installation !== inst) throw new ApiError(401, "invalid_token", "Entitlement not recognized.");
  return p;
}

export function refresh(ctx: Ctx, i: { token: unknown; installationId: unknown }) {
  const p = ownTokenPayload(ctx, i.token, i.installationId);
  limited(ctx, `refresh:inst:${p.installation}`, 60);
  const act = get(ctx.db, "SELECT * FROM activations WHERE id = ?", p.activation);
  if (!act || !act.active) throw new ApiError(403, "device_deactivated", "This Mac was deactivated. Activate it again to continue.");
  const owner: Owner = { customerId: p.customer, trialId: act.trial_id ?? undefined, licenseId: act.license_id ?? undefined };
  run(ctx.db, "UPDATE activations SET last_seen_at = ? WHERE id = ?", ctx.now(), act.id);
  if (act.license_id) {
    const lic = get(ctx.db, "SELECT status, revoke_reason FROM licenses WHERE id = ?", act.license_id) as Row;
    if (lic.status !== "active") throw new ApiError(403, "revoked", "This license is no longer active.", { reason: lic.revoke_reason });
    return issueToken(ctx, { kind: "pro", owner, installation: p.installation, activationId: act.id, expiresAt: null });
  }
  const trial = get(ctx.db, "SELECT * FROM trials WHERE id = ?", act.trial_id) as Row;
  // A customer who has since bought Pro gets it on refresh only through activation, never silently.
  return issueToken(ctx, { kind: "trial", owner, installation: p.installation, activationId: act.id, expiresAt: trial.expires_at, startedAt: trial.started_at });
}

export function listDevices(ctx: Ctx, i: { token: unknown; installationId: unknown }) {
  const p = ownTokenPayload(ctx, i.token, i.installationId);
  const act = get(ctx.db, "SELECT * FROM activations WHERE id = ? AND active = 1", p.activation);
  if (!act) throw new ApiError(403, "device_deactivated", "This Mac is not active.");
  const owner: Owner = { customerId: p.customer, trialId: act.trial_id ?? undefined, licenseId: act.license_id ?? undefined };
  return { devices: devicesOf(ctx, owner).map((d) => ({ ...d, this_device: d.id === act.id })), max_devices: act.license_id ? (get(ctx.db, "SELECT max_devices FROM licenses WHERE id = ?", act.license_id) as Row).max_devices : ctx.cfg.policy.maxDevices };
}

export function deactivate(ctx: Ctx, i: { token: unknown; installationId: unknown }) {
  const p = ownTokenPayload(ctx, i.token, i.installationId);
  run(ctx.db, "UPDATE activations SET active = 0, deactivated_at = ? WHERE id = ? AND active = 1", ctx.now(), p.activation);
  audit(ctx, "device_deactivated", p.customer, { activation: p.activation });
  return { ok: true };
}

/** Frees one device using the short-lived token from a device_limit error, then activates this installation. */
export function releaseAndActivate(ctx: Ctx, i: { manageToken: unknown; deviceId: unknown; installationId: unknown; deviceName: unknown }) {
  const inst = checkInstallation(i.installationId);
  const row = get(ctx.db, "SELECT * FROM manage_tokens WHERE token_hmac = ?", hmacHex(ctx.cfg.secrets.codes, "manage", String(i.manageToken ?? "")));
  if (!row || row.used_at || ctx.now() > row.expires_at) throw new ApiError(400, "invalid_token", "This request expired. Sign in again.");
  const owner: Owner = { customerId: row.customer_id, trialId: row.trial_id ?? undefined, licenseId: row.license_id ?? undefined };
  const [w, v] = ownerWhere(owner);
  return tx(ctx.db, () => {
    const dev = get(ctx.db, `SELECT id FROM activations WHERE id = ? AND ${w} AND active = 1`, String(i.deviceId ?? ""), v);
    if (!dev) throw new ApiError(404, "device_not_found", "That device is not active on this license.");
    run(ctx.db, "UPDATE activations SET active = 0, deactivated_at = ? WHERE id = ?", ctx.now(), dev.id);
    run(ctx.db, "UPDATE manage_tokens SET used_at = ? WHERE id = ?", ctx.now(), row.id);
    const max = owner.licenseId ? (get(ctx.db, "SELECT max_devices FROM licenses WHERE id = ?", owner.licenseId) as Row).max_devices : ctx.cfg.policy.maxDevices;
    const a = activate(ctx, owner, inst, cleanDeviceName(i.deviceName), max);
    if ("full" in a) throw new ApiError(409, "device_limit", "Still at the device limit.");
    audit(ctx, "device_released", owner.customerId, { removed: dev.id });
    if (owner.licenseId) return { ...issueToken(ctx, { kind: "pro", owner, installation: inst, activationId: a.id, expiresAt: null }), license_id: owner.licenseId, trial_expired: false, license_revoked: false };
    const trial = get(ctx.db, "SELECT * FROM trials WHERE id = ?", owner.trialId) as Row;
    return { ...issueToken(ctx, { kind: "trial", owner, installation: inst, activationId: a.id, expiresAt: trial.expires_at, startedAt: trial.started_at }), trial_expired: ctx.now() >= trial.expires_at, license_revoked: false };
  });
}

// ---------------------------------------------------------------- web recovery (emails the key; never displays it)

export async function recoverVerify(ctx: Ctx, i: { email: unknown; code: unknown; ip: string }) {
  const email = normalizeEmail(i.email);
  limited(ctx, `verify:ip:${i.ip}`, ctx.cfg.rate.verifyPerIpHour);
  consumeCode(ctx, email, String(i.code ?? ""), "web_recover");
  const lic = get(ctx.db, "SELECT l.* FROM licenses l JOIN customers c ON c.id = l.customer_id WHERE c.canon = ? AND l.status = 'active' ORDER BY l.created_at DESC LIMIT 1", canonicalEmail(email));
  if (lic) {
    await ctx.mail.send({ to: email, subject: "Your TidyMac license key", text: licenseEmailText(decryptSecret(ctx.cfg.secrets.licenseKeys, lic.key_enc)) });
    audit(ctx, "license_resent", lic.customer_id, { license: lic.id });
  }
  return { ok: true, message: "If a TidyMac license exists for this address, we've emailed it." };
}

const licenseEmailText = (key: string) =>
  `Thank you for buying TidyMac Pro.\n\nYour license key: ${key}\n\nIn TidyMac open Settings > License > Activate License and paste it. It works on up to two of your Macs.\nTo restore Pro on a Mac later you can also use Settings > License > Recover Purchase with this email address.\n\nKeep this email; the key is the proof of purchase.`;

// ---------------------------------------------------------------- checkout and purchases

export async function createCheckout(ctx: Ctx, i: { email?: unknown; ip: string }) {
  limited(ctx, `checkout:ip:${i.ip}`, 30);
  const email = i.email ? normalizeEmail(i.email) : undefined;
  const id = randomId("chk");
  run(ctx.db, "INSERT INTO checkouts(id, provider, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", id, ctx.provider.name, email ?? null, ctx.now(), ctx.now());
  const r = await ctx.provider.createCheckout({ checkoutId: id, email, returnUrl: `${ctx.cfg.websiteUrl}/purchase-success/?checkout_id=${id}` });
  run(ctx.db, "UPDATE checkouts SET provider_ref = ? WHERE id = ?", r.providerRef ?? null, id);
  audit(ctx, "checkout_created", null, { checkout: id, provider: ctx.provider.name });
  return { url: r.url, checkout_id: id, test_mode: ctx.provider.mode !== "live" };
}

/** Status for the website's success page. This is information only: it never activates or unlocks anything. */
export function checkoutStatus(ctx: Ctx, checkoutId: unknown) {
  const c = get(ctx.db, "SELECT status FROM checkouts WHERE id = ?", String(checkoutId ?? ""));
  if (!c) return { status: "unknown" };
  return { status: c.status === "completed" ? "confirmed" : c.status === "created" ? "pending" : c.status };
}

export type WebhookResult = { status: "processed" | "duplicate" | "ignored" };

export async function handleWebhook(ctx: Ctx, raw: string, headers: Record<string, string | undefined>): Promise<WebhookResult> {
  ctx.provider.verifyWebhook(raw, headers, ctx.now()); // throws 401: nothing below runs for an unauthenticated request
  const ev = ctx.provider.parseEvent(raw, headers);
  const existing = get(ctx.db, "SELECT id, state FROM webhook_events WHERE provider = ? AND event_id = ?", ctx.provider.name, ev.eventId);
  if (existing && (existing.state === "processed" || existing.state === "ignored")) return { status: "duplicate" };
  const rowId = existing?.id ?? randomId("whe");
  if (!existing) run(ctx.db, "INSERT INTO webhook_events(id, provider, event_id, event_type, state, payload_sha256, received_at) VALUES (?, ?, ?, ?, 'received', ?, ?)", rowId, ctx.provider.name, ev.eventId, ev.type, sha256hex(raw), ctx.now());
  const done = (state: "processed" | "ignored", error: string | null = null): WebhookResult => {
    run(ctx.db, "UPDATE webhook_events SET state = ?, error = ?, processed_at = ? WHERE id = ?", state, error, ctx.now(), rowId);
    return { status: state };
  };
  try {
    if (ev.type === "ignored") return done("ignored");
    if (!ev.orderId) throw new Error("event has no order id");

    if (ev.type === "purchase_completed") {
      const facts = await ctx.provider.verifyPurchase(ev.orderId);
      if (facts && !facts.completed) { audit(ctx, "purchase_not_completed", null, { order: ev.orderId }); return done("ignored", "provider says not completed"); }
      const price = facts?.priceId ?? ev.priceId;
      if (price !== ctx.priceId) { audit(ctx, "price_mismatch", null, { order: ev.orderId, price }); return done("ignored", "price id does not match the configured product"); }
      const email = normalizeEmail(facts?.email ?? ev.email);
      const simulated = ctx.provider.name === "mock" ? 1 : 0;
      let issued: { key: string; email: string } | null = null;
      tx(ctx.db, () => {
        const c = { id: findOrCreateCustomer(ctx, email, false) };
        let p = get(ctx.db, "SELECT id FROM purchases WHERE provider = ? AND provider_order_id = ?", ctx.provider.name, ev.orderId);
        if (!p) {
          const id = randomId("pur");
          run(ctx.db, "INSERT INTO purchases(id, provider, provider_order_id, customer_id, checkout_id, status, price_id, currency, amount_minor, simulated, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)", id, ctx.provider.name, ev.orderId, c.id, ev.checkoutId && get(ctx.db, "SELECT 1 AS x FROM checkouts WHERE id = ?", ev.checkoutId) ? ev.checkoutId : null, price ?? null, facts?.currency ?? ev.currency ?? null, facts?.amountMinor ?? ev.amountMinor ?? null, simulated, ctx.now(), ctx.now());
          p = { id };
        }
        if (!get(ctx.db, "SELECT 1 AS x FROM licenses WHERE purchase_id = ?", p.id)) {
          const key = generateLicenseKey();
          run(ctx.db, "INSERT INTO licenses(id, customer_id, purchase_id, key_hmac, key_enc, max_devices, simulated, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", randomId("lic"), c.id, p.id, keyHmac(ctx, key), encryptSecret(ctx.cfg.secrets.licenseKeys, key), ctx.cfg.policy.maxDevices, simulated, ctx.now());
          issued = { key, email };
          audit(ctx, "license_issued", c.id, { purchase: p.id, simulated: !!simulated });
        }
        if (ev.checkoutId) run(ctx.db, "UPDATE checkouts SET status = 'completed', updated_at = ? WHERE id = ?", ctx.now(), ev.checkoutId);
      });
      if (issued) {
        const { key, email: to } = issued;
        try {
          await ctx.mail.send({ to, subject: ctx.provider.mode === "live" ? "Your TidyMac Pro license" : "[TEST MODE] Your TidyMac Pro license", text: licenseEmailText(key) });
        } catch {
          audit(ctx, "license_email_failed", null, { order: ev.orderId }); // customer can use Recover Purchase
        }
      }
      return done("processed");
    }

    // refund (full) or chargeback
    const p = get(ctx.db, "SELECT id, customer_id FROM purchases WHERE provider = ? AND provider_order_id = ?", ctx.provider.name, ev.orderId);
    if (!p) throw new Error("purchase not found yet; the provider will retry");
    const status = ev.type === "purchase_chargeback" ? "chargeback" : "refunded";
    tx(ctx.db, () => {
      run(ctx.db, "UPDATE purchases SET status = ?, updated_at = ? WHERE id = ?", status, ctx.now(), p.id);
      run(ctx.db, "UPDATE licenses SET status = 'revoked', revoked_at = ?, revoke_reason = ? WHERE purchase_id = ? AND status = 'active'", ctx.now(), status, p.id);
      audit(ctx, "license_revoked", p.customer_id, { purchase: p.id, reason: status });
    });
    return done("processed");
  } catch (e) {
    run(ctx.db, "UPDATE webhook_events SET state = 'failed', error = ? WHERE id = ?", String((e as Error).message).slice(0, 300), rowId);
    throw new ApiError(500, "webhook_failed", "event processing failed; it will be retried");
  }
}

// ---------------------------------------------------------------- sign in with Google (browser round trip, app polls)
//
// 1. The app generates a random `code_verifier`, keeps it in memory and sends only its SHA-256 `code_challenge` (start).
// 2. The browser goes: website /signin/ -> API /begin -> Google -> API /callback -> website "you're signed in" page.
// 3. The app polls with its `code_verifier`; only the app that started the login can redeem it, once.
// No custom URL scheme and no token ever travels through the browser, so there is nothing for another app to intercept.

const b64url = (b: Buffer) => b.toString("base64url");
const challengeOf = (verifier: string) => b64url(crypto.createHash("sha256").update(verifier).digest());
const stateHmac = (ctx: Ctx, state: string) => hmacHex(ctx.cfg.secrets.codes, "oauth-state", state);

export function startWebSignin(ctx: Ctx, i: { installationId: unknown; codeChallenge: unknown; ip: string }) {
  const inst = checkInstallation(i.installationId);
  const challenge = String(i.codeChallenge ?? "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) throw new ApiError(400, "invalid_challenge", "invalid code challenge");
  limited(ctx, `signin:ip:${i.ip}`, ctx.cfg.rate.codePerIpHour);
  limited(ctx, `signin:inst:${inst}`, ctx.cfg.rate.codePerInstallationHour);
  const id = randomId("sig");
  run(ctx.db, "INSERT INTO login_sessions(id, installation_id, challenge, created_at, expires_at) VALUES (?, ?, ?, ?, ?)", id, inst, challenge, ctx.now(), ctx.now() + ctx.cfg.signinTtlSec);
  audit(ctx, "signin_started", null, { provider: ctx.identity.name });
  return { session_id: id, login_url: `${ctx.cfg.websiteUrl}/signin/?s=${encodeURIComponent(id)}`, expires_in: ctx.cfg.signinTtlSec, poll_interval: 2 };
}

/** The browser arrives from our website: redirect to the identity provider with a fresh state, nonce and PKCE challenge. */
export function beginProvider(ctx: Ctx, sessionId: unknown): string {
  const s = get(ctx.db, "SELECT * FROM login_sessions WHERE id = ?", String(sessionId ?? ""));
  if (!s || s.status !== "pending" || ctx.now() > s.expires_at) throw new ApiError(410, "signin_expired", "This sign-in link has expired. Go back to TidyMac and start again.");
  const state = crypto.randomBytes(24).toString("base64url");
  const nonce = crypto.randomBytes(16).toString("base64url");
  const verifier = crypto.randomBytes(32).toString("base64url");
  run(ctx.db, "UPDATE login_sessions SET status = 'begun', state_hmac = ?, nonce = ?, pkce_verifier = ? WHERE id = ?", stateHmac(ctx, state), nonce, verifier, s.id);
  return ctx.identity.authorizationUrl({ redirectUri: `${ctx.cfg.apiUrl}/v1/auth/google/callback`, state, nonce, codeChallenge: challengeOf(verifier) });
}

/** The provider redirected back. Returns where to send the browser next (always a page on our website). */
export async function completeProvider(ctx: Ctx, i: { state: unknown; code: unknown; error?: unknown }): Promise<string> {
  const done = (p: string) => `${ctx.cfg.websiteUrl}/signin-${p}/`;
  const s = get(ctx.db, "SELECT * FROM login_sessions WHERE state_hmac = ? AND status = 'begun'", stateHmac(ctx, String(i.state ?? "")));
  if (!s || ctx.now() > s.expires_at) return done("failed"); // unknown/replayed state or too slow: nothing is trusted
  if (i.error || !i.code) {
    run(ctx.db, "UPDATE login_sessions SET status = 'denied', state_hmac = NULL WHERE id = ?", s.id);
    audit(ctx, "signin_denied", null, { reason: "provider_error" });
    return done("failed");
  }
  try {
    const who = await ctx.identity.exchange({ code: String(i.code), redirectUri: `${ctx.cfg.apiUrl}/v1/auth/google/callback`, codeVerifier: s.pkce_verifier, nonce: s.nonce, nowSec: ctx.now() });
    const email = normalizeEmail(who.email);
    tx(ctx.db, () => {
      const customerId = findOrCreateCustomer(ctx, email, true);
      // state is single use: clearing it makes a replayed callback fail
      run(ctx.db, "UPDATE login_sessions SET status = 'authenticated', customer_id = ?, state_hmac = NULL, pkce_verifier = NULL WHERE id = ?", customerId, s.id);
      audit(ctx, "signin_authenticated", customerId, { provider: ctx.identity.name });
    });
    return done("done");
  } catch (e) {
    run(ctx.db, "UPDATE login_sessions SET status = 'denied', state_hmac = NULL, pkce_verifier = NULL WHERE id = ?", s.id);
    audit(ctx, "signin_denied", null, { reason: e instanceof ApiError ? e.code : "error" });
    return done("failed");
  }
}

/** The app asks "is it done yet?". Only the holder of the code_verifier can redeem, and only once. */
export function pollWebSignin(ctx: Ctx, i: { sessionId: unknown; codeVerifier: unknown; installationId: unknown; deviceName: unknown }) {
  const inst = checkInstallation(i.installationId);
  const s = get(ctx.db, "SELECT * FROM login_sessions WHERE id = ?", String(i.sessionId ?? ""));
  const verifier = String(i.codeVerifier ?? "");
  // identical answer for "no such session" and "wrong verifier": nothing to probe
  if (!s || s.installation_id !== inst || !safeEqual(challengeOf(verifier), s.challenge)) throw new ApiError(404, "signin_unknown", "Unknown sign-in. Start again from TidyMac.");
  limited(ctx, `poll:${s.id}`, 400, 600);
  if (ctx.now() > s.expires_at && s.status !== "consumed") throw new ApiError(410, "signin_expired", "This sign-in expired. Start again.");
  if (s.status === "consumed") throw new ApiError(410, "signin_used", "This sign-in was already used.");
  if (s.status === "denied") throw new ApiError(403, "signin_denied", "The sign-in was cancelled or could not be verified.");
  if (s.status !== "authenticated") return { status: "pending" as const };
  const claimed = run(ctx.db, "UPDATE login_sessions SET status = 'consumed' WHERE id = ? AND status = 'authenticated'", s.id);
  if (Number(claimed.changes) !== 1) throw new ApiError(410, "signin_used", "This sign-in was already used.");
  return { status: "done" as const, ...resolveForCustomer(ctx, s.customer_id, inst, cleanDeviceName(i.deviceName)) };
}

/** Development/test only: finish a MOCK sign-in for the given email (what the simulated Google page posts). */
export async function completeMockSignin(ctx: Ctx, state: string, email: string): Promise<string> {
  return completeProvider(ctx, { state, code: email });
}
