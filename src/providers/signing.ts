import crypto from "node:crypto";
import { ApiError } from "../errors.ts";
import { safeEqual } from "../crypto.ts";

/** Paddle's scheme: header `ts=<unix>;h1=<hex>`, h1 = HMAC-SHA256(secret, `${ts}:${rawBody}`). */
export const signWebhookBody = (secret: string, ts: number, raw: string) =>
  crypto.createHmac("sha256", secret).update(`${ts}:${raw}`).digest("hex");

export function verifyTsH1(header: string | undefined, secret: string, raw: string, nowSec: number, toleranceSec: number) {
  const bad = (m: string) => new ApiError(401, "invalid_signature", m);
  if (!header) throw bad("missing signature");
  const parts = header.split(";").map((p) => p.trim().split("="));
  const ts = Number(parts.find((p) => p[0] === "ts")?.[1]);
  const sigs = parts.filter((p) => p[0] === "h1").map((p) => p[1] ?? "");
  if (!Number.isFinite(ts) || sigs.length === 0) throw bad("malformed signature");
  if (Math.abs(nowSec - ts) > toleranceSec) throw bad("stale signature");
  const expected = signWebhookBody(secret, ts, raw);
  if (!sigs.some((s) => safeEqual(s, expected))) throw bad("signature mismatch");
}
