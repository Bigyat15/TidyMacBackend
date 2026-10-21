import { ApiError } from "../errors.ts";
import type { PaymentEvent, PaymentProvider, PurchaseFacts } from "./types.ts";
import { verifyTsH1 } from "./signing.ts";

/** Maps a Paddle Billing webhook body to a provider-independent event. Shared with the mock adapter's fixtures. */
export function parsePaddleEvent(raw: string): PaymentEvent {
  let e: any;
  try {
    e = JSON.parse(raw);
  } catch {
    throw new ApiError(400, "invalid_body", "webhook body is not JSON");
  }
  const eventId = String(e?.event_id ?? "");
  if (!eventId) throw new ApiError(400, "invalid_body", "missing event_id");
  const d = e.data ?? {};
  switch (e.event_type) {
    case "transaction.completed": {
      const item = Array.isArray(d.items) ? d.items[0] : undefined;
      return {
        eventId, type: "purchase_completed", orderId: d.id, customerRef: d.customer_id ?? undefined,
        priceId: item?.price?.id ?? item?.price_id, currency: d.currency_code,
        amountMinor: d.details?.totals?.total !== undefined ? Number(d.details.totals.total) : undefined,
        checkoutId: d.custom_data?.checkout_id, email: d.custom_data?.mock_email, simulated: e.simulated === true,
      };
    }
    case "adjustment.created":
    case "adjustment.updated": {
      if (d.status !== "approved") return { eventId, type: "ignored" };
      if (d.action === "chargeback") return { eventId, type: "purchase_chargeback", orderId: d.transaction_id, simulated: e.simulated === true };
      // Only FULL refunds revoke the license; partial refunds and credits are recorded but ignored (published policy).
      if (d.action === "refund" && d.type === "full") return { eventId, type: "purchase_refunded", orderId: d.transaction_id, simulated: e.simulated === true };
      return { eventId, type: "ignored" };
    }
    default:
      return { eventId, type: "ignored" };
  }
}

export interface PaddleOptions {
  apiKey: string;
  webhookSecret: string;
  priceId: string;
  mode: "sandbox" | "live";
  toleranceSec: number;
  fetchImpl?: typeof fetch;
}

export class PaddleProvider implements PaymentProvider {
  readonly name = "paddle" as const;
  readonly mode: "sandbox" | "live";
  private base: string;
  private f: typeof fetch;
  private o: PaddleOptions;
  constructor(o: PaddleOptions) {
    this.o = o;
    this.mode = o.mode;
    this.base = o.mode === "live" ? "https://api.paddle.com" : "https://sandbox-api.paddle.com";
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

  async createCheckout({ checkoutId }: { checkoutId: string; email?: string }) {
    // Needs a default payment link configured in the Paddle dashboard (see docs/PAYMENT_PROVIDER_SETUP.md).
    const r = await this.api("/transactions", {
      method: "POST",
      body: JSON.stringify({ items: [{ price_id: this.o.priceId, quantity: 1 }], custom_data: { checkout_id: checkoutId } }),
    });
    const url: string | undefined = r?.data?.checkout?.url;
    if (!url) throw new ApiError(502, "checkout_unavailable", "provider returned no checkout URL; set a default payment link in Paddle");
    return { url, providerRef: r.data.id as string };
  }

  verifyWebhook(raw: string, headers: Record<string, string | undefined>, nowSec: number) {
    verifyTsH1(headers["paddle-signature"], this.o.webhookSecret, raw, nowSec, this.o.toleranceSec);
  }

  parseEvent = parsePaddleEvent;

  async verifyPurchase(orderId: string): Promise<PurchaseFacts> {
    const t = (await this.api(`/transactions/${encodeURIComponent(orderId)}`)).data;
    const item = Array.isArray(t.items) ? t.items[0] : undefined;
    let email: string | undefined;
    if (t.customer_id) email = (await this.api(`/customers/${encodeURIComponent(t.customer_id)}`)).data?.email;
    return {
      orderId, completed: t.status === "completed", email, priceId: item?.price?.id ?? item?.price_id,
      currency: t.currency_code, amountMinor: t.details?.totals?.total !== undefined ? Number(t.details.totals.total) : undefined,
    };
  }

  async getPurchaseStatus(orderId: string) {
    return { status: String((await this.api(`/transactions/${encodeURIComponent(orderId)}`)).data?.status ?? "unknown") };
  }
}
