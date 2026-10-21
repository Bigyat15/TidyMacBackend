import crypto from "node:crypto";
import { ApiError } from "../errors.ts";
import { safeEqual } from "../crypto.ts";
import type { PaymentEvent, PaymentProvider, PurchaseFacts } from "./types.ts";

/**
 * Dodo Payments (https://docs.dodopayments.com): hosted Checkout Sessions + Standard Webhooks.
 * Plain REST (no SDK): the backend deliberately has no runtime dependencies. Signature verification follows the
 * documented manual procedure: HMAC-SHA256 over `${webhook-id}.${webhook-timestamp}.${rawBody}` keyed by the base64
 * secret (after `whsec_`), compared in constant time against every `v1,<sig>` in `webhook-signature`.
 */

export function signStandardWebhook(secret: string, id: string, ts: number, raw: string): string {
  const key = Buffer.from(secret.startsWith("whsec_") ? secret.slice(6) : secret, "base64");
  return "v1," + crypto.createHmac("sha256", key).update(`${id}.${ts}.${raw}`).digest("base64");
}

export function verifyStandardWebhook(headers: Record<string, string | undefined>, secret: string, raw: string, nowSec: number, toleranceSec: number) {
  const bad = (m: string) => new ApiError(401, "invalid_signature", m);
  const id = headers["webhook-id"], tsRaw = headers["webhook-timestamp"], sigHeader = headers["webhook-signature"];
  if (!id || !tsRaw || !sigHeader) throw bad("missing signature headers");
  const ts = Number(tsRaw);
  if (!Number.isFinite(ts)) throw bad("malformed timestamp");
  if (Math.abs(nowSec - ts) > toleranceSec) throw bad("stale signature");
  const expected = signStandardWebhook(secret, id, ts, raw);
  const given = sigHeader.split(" ").filter((s) => s.startsWith("v1,"));
  if (!given.some((s) => safeEqual(s, expected))) throw bad("signature mismatch");
}

/** The configured product must be the ONLY item in the cart; anything else can never match `ctx.priceId`. */
const productOf = (cart: any): string | undefined => (Array.isArray(cart) && cart.length === 1 ? cart[0]?.product_id : Array.isArray(cart) && cart.length > 1 ? "multi-item-cart" : undefined);

export function parseDodoEvent(raw: string, headers: Record<string, string | undefined> = {}): PaymentEvent {
  let e: any;
  try {
    e = JSON.parse(raw);
  } catch {
    throw new ApiError(400, "invalid_body", "webhook body is not JSON");
  }
  const eventId = String(headers["webhook-id"] ?? "");
  if (!eventId) throw new ApiError(400, "invalid_body", "missing webhook-id");
  const d = e?.data ?? {};
  switch (e?.type) {
    case "payment.succeeded":
      return {
        eventId, type: "purchase_completed", orderId: d.payment_id, customerRef: d.customer?.customer_id, email: d.customer?.email,
        priceId: productOf(d.product_cart), currency: d.currency, amountMinor: d.total_amount !== undefined ? Number(d.total_amount) : undefined,
        checkoutId: d.metadata?.checkout_id,
      };
    case "refund.succeeded":
      // Only FULL refunds revoke the license; partial refunds are recorded but ignored (published policy).
      return d.is_partial === false && d.payment_id ? { eventId, type: "purchase_refunded", orderId: d.payment_id } : { eventId, type: "ignored" };
    case "dispute.lost":
    case "dispute.accepted":
      return d.payment_id ? { eventId, type: "purchase_chargeback", orderId: d.payment_id } : { eventId, type: "ignored" };
    default:
      // payment.failed / cancelled / processing, dispute.opened / challenged / won / cancelled / expired, subscriptions...
      return { eventId, type: "ignored" };
  }
}

export interface DodoOptions {
  apiKey: string;
  webhookSecret: string;
  productId: string;
  returnUrl: string;
  mode: "sandbox" | "live";
  toleranceSec: number;
  fetchImpl?: typeof fetch;
}

export class DodoProvider implements PaymentProvider {
  readonly name = "dodo" as const;
  readonly mode: "sandbox" | "live";
  private base: string;
  private f: typeof fetch;
  private o: DodoOptions;
  constructor(o: DodoOptions) {
    this.o = o;
    this.mode = o.mode;
    this.base = o.mode === "live" ? "https://live.dodopayments.com" : "https://test.dodopayments.com";
    this.f = o.fetchImpl ?? fetch;
  }

  private async api(path: string, init: RequestInit = {}) {
    const r = await this.f(`${this.base}${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${this.o.apiKey}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
    });
    if (!r.ok) throw new ApiError(502, "provider_error", `payment provider returned HTTP ${r.status}`);
    return (await r.json()) as any;
  }

  async createCheckout({ checkoutId, email, returnUrl }: { checkoutId: string; email?: string; returnUrl?: string }) {
    // The product (and so the price) is chosen here from server configuration; nothing from the client reaches the cart.
    const r = await this.api("/checkouts", {
      method: "POST",
      body: JSON.stringify({
        product_cart: [{ product_id: this.o.productId, quantity: 1 }],
        ...(email ? { customer: { email } } : {}),
        metadata: { checkout_id: checkoutId },
        return_url: returnUrl ?? this.o.returnUrl,
      }),
    });
    if (!r?.checkout_url) throw new ApiError(502, "checkout_unavailable", "provider returned no checkout URL");
    return { url: String(r.checkout_url), providerRef: r.session_id as string | undefined };
  }

  verifyWebhook(raw: string, headers: Record<string, string | undefined>, nowSec: number) {
    verifyStandardWebhook(headers, this.o.webhookSecret, raw, nowSec, this.o.toleranceSec);
  }

  parseEvent = parseDodoEvent;

  async verifyPurchase(orderId: string): Promise<PurchaseFacts> {
    const p = await this.api(`/payments/${encodeURIComponent(orderId)}`);
    return { orderId, completed: p.status === "succeeded", email: p.customer?.email, priceId: productOf(p.product_cart), currency: p.currency, amountMinor: p.total_amount !== undefined ? Number(p.total_amount) : undefined };
  }

  async getPurchaseStatus(orderId: string) {
    return { status: String((await this.api(`/payments/${encodeURIComponent(orderId)}`)).status ?? "unknown") };
  }
}
