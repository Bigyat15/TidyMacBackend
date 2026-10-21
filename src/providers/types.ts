export type PaymentEventType = "purchase_completed" | "purchase_refunded" | "purchase_chargeback" | "ignored";

/** Provider-independent view of a webhook event. Core licensing code only ever sees this. */
export interface PaymentEvent {
  eventId: string;
  type: PaymentEventType;
  orderId?: string;
  customerRef?: string;
  email?: string;
  priceId?: string;
  currency?: string;
  amountMinor?: number;
  checkoutId?: string;
  /** True only for events produced by the development mock adapter. */
  simulated?: boolean;
}

export interface PurchaseFacts {
  orderId: string;
  completed: boolean;
  email?: string;
  priceId?: string;
  currency?: string;
  amountMinor?: number;
}

export interface PaymentProvider {
  readonly name: "mock" | "paddle";
  readonly mode: "mock" | "sandbox" | "live";
  /** Hosted checkout for the configured one-time product. The price comes from provider configuration, never from the client. */
  createCheckout(input: { checkoutId: string; email?: string }): Promise<{ url: string; providerRef?: string }>;
  /** Throws ApiError(401) unless the signature is valid and fresh. Must be called with the exact raw request body. */
  verifyWebhook(raw: string, headers: Record<string, string | undefined>, nowSec: number): void;
  parseEvent(raw: string): PaymentEvent;
  /** Independently re-checks a purchase with the provider's API. `null` when the adapter cannot (mock). */
  verifyPurchase(orderId: string): Promise<PurchaseFacts | null>;
  getPurchaseStatus(orderId: string): Promise<{ status: string }>;
}
