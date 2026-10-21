# Dodo Payments setup

TidyMac sells ONE one-time product (TidyMac Pro). No subscriptions, so there is no renewal logic and no customer portal.
Dodo is a payment provider behind the same interface as Paddle (`server/src/providers/dodo.ts`); everything after the
verified webhook (license issue, email, device limits, revocation) is shared code.

## Flow
1. App or website calls `POST /v1/checkout` (no price, plan or product from the client).
2. Server stores a pending `checkouts` row, then creates a Dodo **Checkout Session** (`POST {host}/checkouts`) for the
   product in `DODO_PAYMENTS_PRODUCT_ID`, with `metadata.checkout_id` and a `return_url`. Only the URL and checkout id go back.
3. The customer pays on Dodo's hosted page. The return page (`/purchase-success/?checkout_id=`) is informational only.
4. Dodo calls `POST https://api.bigyatthapa.com.np/v1/webhooks/dodo`. The server verifies the Standard Webhooks signature
   on the raw body (HMAC-SHA256 of `id.timestamp.body`, 5-minute window, constant-time), deduplicates by `webhook-id`,
   re-fetches the payment from Dodo (`GET /payments/{id}`) and requires status `succeeded` and the configured product as the
   only cart item. Only then is a license created and emailed. Fulfilment is idempotent per payment id.
5. The customer activates with the key, or signs in with the same email. The app never proves payment itself.

## Environment (names only)
`PAYMENT_PROVIDER=dodo`, `DODO_PAYMENTS_ENVIRONMENT` (`test_mode` | `live_mode`), `DODO_PAYMENTS_API_KEY`,
`DODO_PAYMENTS_WEBHOOK_SECRET`, `DODO_PAYMENTS_PRODUCT_ID`, optional `DODO_PAYMENTS_RETURN_URL`
(default `<WEBSITE_URL>/purchase-success/`). The public API address is the existing `LICENSE_API_URL`.
`staging` requires `test_mode`; `production` requires `live_mode`; mixing is refused at startup.
Test and live use different Dodo keys, products, webhook endpoints and secrets: configure them separately.

## Dashboard setup (test mode first)
1. Dodo dashboard in **Test Mode** -> Products -> create a **one-time** product "TidyMac Pro" with your price. The price lives
   here, not in app code. Copy its product id (`pdt_...`) into `DODO_PAYMENTS_PRODUCT_ID`.
2. Developer -> API keys: create a key, put it in `DODO_PAYMENTS_API_KEY`.
3. Developer -> Webhooks -> add endpoint `https://api.bigyatthapa.com.np/v1/webhooks/dodo` and enable at least:
   `payment.succeeded`, `payment.failed`, `payment.cancelled`, `refund.succeeded`, `dispute.opened`, `dispute.lost`,
   `dispute.accepted`, `dispute.won`. Other events are acknowledged and ignored.
4. Open the endpoint and copy its signing secret (`whsec_...`) into `DODO_PAYMENTS_WEBHOOK_SECRET`.
5. Restart the service, buy once in test mode using Dodo's documented test payment details, confirm the license email arrives.

## Policy
| Event | Result |
|---|---|
| `payment.succeeded` (verified with Dodo) | license issued once |
| `payment.failed` / `cancelled` / `processing` | nothing |
| `refund.succeeded`, full | license revoked; partial refunds are recorded, license stays |
| `dispute.lost` / `dispute.accepted` | license revoked (chargeback) |
| `dispute.opened` / `challenged` / `won` / `cancelled` / `expired` | no change |
Events that arrive before their payment return 500 so Dodo retries them (out-of-order safe).

## Launch checklist
- Test-mode purchase, refund and email all verified end to end; webhook deliveries show 200 in the Dodo dashboard.
- Create the live product, live API key and a separate live webhook endpoint/secret; set `APP_ENV=production`,
  `DODO_PAYMENTS_ENVIRONMENT=live_mode` and the live values; restart; make one small real purchase and refund it.
- Confirm account verification and payouts for your country with Dodo before announcing.

## Troubleshooting
- `401 invalid_signature`: wrong secret (test vs live), proxy altering the body, or server clock off by more than 5 minutes.
- Paid but no license: Dodo dashboard -> webhook delivery log; check `journalctl -u tidymac-backend`; product id mismatch is
  recorded as `price_mismatch` in `audit_events`.
- `502 provider_error` at checkout: wrong API key or environment (test key with `live_mode`, or the reverse).

## Not verified
Real Dodo traffic (checkout session creation, delivery of live webhooks) has not been exercised; tests use a faithful
stub of the documented request/response shapes and the documented signature algorithm.
