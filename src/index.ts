import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "./config.ts";
import { openDb } from "./db.ts";
import { ConsoleMailer, ResendMailer } from "./mail.ts";
import { MockProvider } from "./providers/mock.ts";
import { GoogleIdentity } from "./identity/google.ts";
import { MockIdentity } from "./identity/mock.ts";
import { PaddleProvider } from "./providers/paddle.ts";
import { DodoProvider } from "./providers/dodo.ts";
import { createAppServer } from "./app.ts";
import type { Ctx } from "./service.ts";

// Development convenience: load server/.dev/dev.env (created by `npm run dev:setup`) when APP_ENV is not set.
const devEnv = path.join(import.meta.dirname, "..", ".dev", "dev.env");
if (!process.env.APP_ENV && fs.existsSync(devEnv)) {
  for (const line of fs.readFileSync(devEnv, "utf8").split("\n")) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}

export function buildContext(env: NodeJS.ProcessEnv = process.env): Ctx {
  const cfg = loadConfig(env); // throws with every problem listed; production never starts half-configured
  const db = openDb(cfg.dbPath);
  const mail = cfg.mail.provider === "resend" ? new ResendMailer(cfg.mail.resendApiKey, cfg.mail.from) : new ConsoleMailer();
  const tol = cfg.policy.webhookToleranceSec;
  const mode = cfg.provider.mode as "sandbox" | "live";
  const provider =
    cfg.provider.name === "paddle" ? new PaddleProvider({ ...cfg.provider.paddle, mode, toleranceSec: tol })
    : cfg.provider.name === "dodo" ? new DodoProvider({ ...cfg.provider.dodo, mode, toleranceSec: tol })
    : new MockProvider(cfg.apiUrl, cfg.provider.mockWebhookSecret, tol);
  const priceId = cfg.provider.name === "paddle" ? cfg.provider.paddle.priceId : cfg.provider.name === "dodo" ? cfg.provider.dodo.productId : "pri_mock_tidymac_pro";
  const identity = cfg.identity.name === "google" ? new GoogleIdentity({ clientId: cfg.identity.googleClientId, clientSecret: cfg.identity.googleClientSecret }) : new MockIdentity(cfg.apiUrl);
  return { cfg, db, mail, provider, identity, priceId, now: () => Math.floor(Date.now() / 1000) };
}

if (import.meta.main) {
  const ctx = buildContext();
  const server = createAppServer(ctx);
  server.listen(ctx.cfg.port, ctx.cfg.host, () => {
    console.log(`TidyMac licensing API on http://${ctx.cfg.host}:${ctx.cfg.port}  env=${ctx.cfg.env} provider=${ctx.provider.name}/${ctx.provider.mode}`);
    if (ctx.cfg.env === "development") console.log("DEVELOPMENT MODE: mock payments and console email are active.");
  });
  const stop = () => server.close(() => { ctx.db.close(); process.exit(0); });
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
