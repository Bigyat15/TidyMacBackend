# TidyMac backend

Licensing, payments (Dodo Payments; Paddle also supported), email codes (Resend) and Sign in with Google for the TidyMac desktop app and website.
Plain Node.js (24+) with no runtime npm dependencies: it uses `node:sqlite`, `node:http` and `node:crypto`.
`npm install` only brings in test/type tooling.

## Layout
- `src/`: server (`index.ts` entry, `app.ts` routes, `service.ts` logic, `db.ts` schema + migrations, `config.ts` environment).
- `scripts/`: `gen-prod-keys.ts`, `prune.ts` (daily retention), `admin.ts` (operator CLI), `dev-setup.ts` (local development only).
- `test/`: vitest suite. `deploy/`: systemd templates (no secrets).

## Configuration
All settings come from environment variables; see `.env.example` for the full list (names only, no values).
`APP_ENV=staging|production` fails closed: the server refuses to start if a secret, an `https://` URL, `ALLOWED_ORIGINS`
or a real provider (Paddle, Google, Resend) is missing, and it rejects mock providers and development secrets.
Node does not read `.env` files by itself; systemd loads `EnvironmentFile` (see `deploy/`).

Generate the license signing key once: `npm run keys` (store the private key safely and back it up).

## Database and migrations
SQLite file at `DATABASE_PATH` (the directory must exist and be writable by the service user). Migrations run automatically
and idempotently at startup (`schema_migrations` table); current schema version is 2. WAL mode is on, so back up with
`sqlite3 <db> ".backup '<file>'"`, not by copying the file while running.

## Run
```
npm ci --omit=dev     # no runtime dependencies; optional
npm start             # node src/index.ts
curl http://127.0.0.1:8787/health   # {"ok":true}
```
Binds to `HOST` (default `127.0.0.1`) and `PORT` (default 8787). Put a TLS reverse proxy in front and set `TRUST_PROXY=1`.
`npm run prune` should run daily (`deploy/tidymac-prune.timer`).

## Tests
`npm ci && npm run typecheck && npm test` (61 tests; they use in-memory databases and local ports, never real providers).

## API (unchanged contract)
`GET /health` · payment webhook `POST /v1/webhooks/dodo` (Dodo) · `POST /v1/auth/request-code`, `/v1/auth/verify`, `/v1/auth/oauth/start`, `/v1/auth/oauth/poll` ·
`GET /v1/auth/google/begin`, `/v1/auth/google/callback` · `POST /v1/license/activate`, `/v1/entitlement/refresh`,
`/v1/devices/list|deactivate|release` · `POST /v1/checkout`, `GET /v1/checkout/status` · `POST /v1/recover/request|verify` ·
payment webhook (signature verified). `/dev/*` pages exist only with the mock providers in development/test.

## Not verified here
Real Paddle, Google and Resend traffic, and an actual VPS deployment, have not been tested from this repository.
