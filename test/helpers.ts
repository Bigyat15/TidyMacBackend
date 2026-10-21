import { loadConfig, type Config } from "../src/config.ts";
import { openDb } from "../src/db.ts";
import { ConsoleMailer } from "../src/mail.ts";
import { MockProvider } from "../src/providers/mock.ts";
import type { Ctx } from "../src/service.ts";
import { MockIdentity } from "../src/identity/mock.ts";
import { generateKeyPair, publicKeyOf, verifyEntitlement } from "../src/crypto.ts";

export const T0 = 1_800_000_000;

export function makeCtx(over: Record<string, string> = {}, dbPath = ":memory:") {
  const k = generateKeyPair();
  const cfg = loadConfig({ APP_ENV: "test", LICENSE_SIGNING_PRIVATE_KEY: k.privateKeyB64, DATABASE_PATH: dbPath, ...over });
  const mail = new ConsoleMailer(false);
  const provider = new MockProvider(cfg.apiUrl, cfg.provider.mockWebhookSecret, cfg.policy.webhookToleranceSec);
  const clock = { t: T0 };
  const ctx: Ctx = { cfg, db: openDb(cfg.dbPath), mail, provider, identity: new MockIdentity(cfg.apiUrl), priceId: "pri_mock_tidymac_pro", now: () => clock.t };
  return { ctx, mail, provider, clock, cfg: cfg as Config, pub: publicKeyOf(cfg.signing.privateKeyB64) };
}

export const lastCode = (mail: ConsoleMailer, to?: string) => {
  const want = to?.trim().toLowerCase();
  const m = [...mail.outbox].reverse().find((x) => (!want || x.to === want) && /verification code/.test(x.subject));
  return m?.text.match(/code is (\d{6})/)?.[1] ?? "";
};
export const lastKey = (mail: ConsoleMailer) => [...mail.outbox].reverse().map((m) => m.text.match(/TM-[A-Z0-9]{5}(-[A-Z0-9]{5}){3}/)?.[0]).find(Boolean) ?? "";
export const payload = (pub: string, token: string) => verifyEntitlement(pub, token)!;
export const INST = (n: number) => `install-${String(n).padStart(8, "0")}`;
