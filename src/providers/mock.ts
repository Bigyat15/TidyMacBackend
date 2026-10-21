import type { PaymentProvider } from "./types.ts";
import { parsePaddleEvent } from "./paddle.ts";
import { signWebhookBody, verifyTsH1 } from "./signing.ts";

/**
 * DEVELOPMENT / TEST ONLY. Never collects money, never talks to a real provider, and `loadConfig` refuses it in
 * staging and production. Its events are Paddle-shaped (so the real pipeline is exercised) but marked `simulated`,
 * and entitlements issued from them carry mode "test", which release builds of the app reject.
 */
export class MockProvider implements PaymentProvider {
  readonly name = "mock" as const;
  readonly mode = "mock" as const;
  private apiUrl: string;
  private secret: string;
  private toleranceSec: number;
  private priceId: string;
  constructor(apiUrl: string, secret: string, toleranceSec: number, priceId = "pri_mock_tidymac_pro") {
    this.apiUrl = apiUrl;
    this.secret = secret;
    this.toleranceSec = toleranceSec;
    this.priceId = priceId;
  }

  async createCheckout({ checkoutId, email }: { checkoutId: string; email?: string }) {
    const q = new URLSearchParams({ checkout_id: checkoutId, ...(email ? { email } : {}) });
    return { url: `${this.apiUrl}/dev/mock-checkout?${q}`, providerRef: `txn_mock_${checkoutId}` };
  }
  verifyWebhook(raw: string, headers: Record<string, string | undefined>, nowSec: number) {
    verifyTsH1(headers["paddle-signature"], this.secret, raw, nowSec, this.toleranceSec);
  }
  parseEvent = parsePaddleEvent;
  async verifyPurchase() {
    return null; // nothing real to ask
  }
  async getPurchaseStatus() {
    return { status: "mock" };
  }

  /** Test fixtures: a correctly signed simulated webhook. */
  fixture(kind: "completed" | "refund_full" | "refund_partial" | "chargeback", o: { eventId: string; orderId: string; email?: string; checkoutId?: string; priceId?: string; ts: number }) {
    const base = { event_id: o.eventId, occurred_at: new Date(o.ts * 1000).toISOString(), simulated: true };
    const body =
      kind === "completed"
        ? { ...base, event_type: "transaction.completed", data: { id: o.orderId, status: "completed", customer_id: "ctm_mock", currency_code: "USD", items: [{ price: { id: o.priceId ?? this.priceId } }], details: { totals: { total: "2499" } }, custom_data: { checkout_id: o.checkoutId, mock_email: o.email } } }
        : { ...base, event_type: "adjustment.created", data: { id: `adj_${o.eventId}`, status: "approved", transaction_id: o.orderId, action: kind === "chargeback" ? "chargeback" : "refund", type: kind === "refund_partial" ? "partial" : "full" } };
    const raw = JSON.stringify(body);
    return { raw, headers: { "paddle-signature": `ts=${o.ts};h1=${signWebhookBody(this.secret, o.ts, raw)}` } as Record<string, string> };
  }
}
