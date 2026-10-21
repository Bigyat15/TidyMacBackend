import crypto from "node:crypto";

export type AppEnv = "development" | "test" | "staging" | "production";

export interface Config {
  env: AppEnv;
  port: number;
  host: string;
  websiteUrl: string;
  apiUrl: string;
  allowedOrigins: string[];
  dbPath: string;
  trustProxy: boolean;
  signing: { privateKeyB64: string; kid: string };
  /** `live` entitlements are accepted by release builds; `test` ones only by development/staging builds. */
  entitlementMode: "test" | "live";
  secrets: { codes: string; licenseKeys: string };
  policy: {
    trialHours: number;
    maxDevices: number;
    codeTtlSec: number;
    codeMaxAttempts: number;
    offlineGraceDays: number;
    codeCooldownSec: number;
    webhookToleranceSec: number;
  };
  rate: { codePerEmailHour: number; codePerIpHour: number; codePerInstallationHour: number; verifyPerIpHour: number; keyAttemptsPerIpHour: number };
  provider: {
    name: "mock" | "paddle";
    mode: "mock" | "sandbox" | "live";
    mockWebhookSecret: string;
    paddle: { apiKey: string; webhookSecret: string; priceId: string };
  };
  mail: { provider: "console" | "resend"; from: string; resendApiKey: string };
  identity: { name: "google" | "mock"; googleClientId: string; googleClientSecret: string };
  signinTtlSec: number;
}

export class ConfigError extends Error {
  problems: string[];
  constructor(problems: string[]) {
    super(`Invalid configuration:\n - ${problems.join("\n - ")}`);
    this.problems = problems;
  }
}

type E = Record<string, string | undefined>;
const int = (e: E, k: string, d: number) => (e[k] !== undefined && e[k] !== "" ? Number(e[k]) : d);

/**
 * Reads configuration from environment variables. Production and staging FAIL CLOSED: anything missing or unsafe
 * (mock payments, console mail, http URLs, dev keys) throws instead of silently falling back.
 */
export function loadConfig(e: E = process.env): Config {
  const problems: string[] = [];
  const env = (e.APP_ENV ?? "development") as AppEnv;
  if (!["development", "test", "staging", "production"].includes(env)) problems.push("APP_ENV must be development, test, staging or production");
  const strict = env === "production" || env === "staging";
  const need = (k: string, why = "") => {
    if (!e[k]) problems.push(`${k} is required${why ? ` (${why})` : ""}`);
    return e[k] ?? "";
  };

  const providerName = (e.PAYMENT_PROVIDER ?? (strict ? "" : "mock")) as "mock" | "paddle";
  if (!["mock", "paddle"].includes(providerName)) problems.push("PAYMENT_PROVIDER must be mock or paddle");
  const paddleMode = (e.PADDLE_MODE ?? "sandbox") as "sandbox" | "live";
  if (providerName === "paddle" && !["sandbox", "live"].includes(paddleMode)) problems.push("PADDLE_MODE must be sandbox or live");
  if (providerName === "mock" && strict) problems.push("PAYMENT_PROVIDER=mock is not allowed in staging or production");
  if (env === "production" && providerName === "paddle" && paddleMode !== "live") problems.push("production requires PADDLE_MODE=live");
  if (env === "staging" && providerName === "paddle" && paddleMode === "live") problems.push("staging must use PADDLE_MODE=sandbox");

  const mailProvider = (e.EMAIL_PROVIDER ?? (strict ? "" : "console")) as "console" | "resend";
  if (!["console", "resend"].includes(mailProvider)) problems.push("EMAIL_PROVIDER must be console or resend");
  if (mailProvider === "console" && strict) problems.push("EMAIL_PROVIDER=console is not allowed in staging or production");

  const identityName = (e.IDENTITY_PROVIDER ?? (strict ? "" : "mock")) as "google" | "mock";
  if (!["google", "mock"].includes(identityName)) problems.push("IDENTITY_PROVIDER must be google or mock");
  if (identityName === "mock" && strict) problems.push("IDENTITY_PROVIDER=mock is not allowed in staging or production");
  if (identityName === "google") {
    if (!e.GOOGLE_CLIENT_ID) problems.push("GOOGLE_CLIENT_ID is required with IDENTITY_PROVIDER=google");
    if (!e.GOOGLE_CLIENT_SECRET) problems.push("GOOGLE_CLIENT_SECRET is required with IDENTITY_PROVIDER=google");
  }

  const websiteUrl = strict ? need("WEBSITE_URL") : (e.WEBSITE_URL ?? "http://localhost:8080");
  const apiUrl = strict ? need("LICENSE_API_URL") : (e.LICENSE_API_URL ?? `http://127.0.0.1:${int(e, "PORT", 8787)}`);
  if (strict) {
    for (const [k, v] of [["WEBSITE_URL", websiteUrl], ["LICENSE_API_URL", apiUrl]] as const) {
      if (v && !v.startsWith("https://")) problems.push(`${k} must be https:// in ${env}`);
    }
  }
  const dbPath = strict ? need("DATABASE_PATH", "a persistent file path; in-memory databases are refused") : (e.DATABASE_PATH ?? ":memory:");
  if (strict && dbPath === ":memory:") problems.push("DATABASE_PATH must not be :memory: in staging/production");

  const privateKeyB64 = strict ? need("LICENSE_SIGNING_PRIVATE_KEY", "base64 PKCS8 Ed25519 key") : (e.LICENSE_SIGNING_PRIVATE_KEY ?? "");
  const secretCodes = strict ? need("CODE_HMAC_SECRET") : (e.CODE_HMAC_SECRET ?? "dev-only-code-secret");
  const secretKeys = strict ? need("LICENSE_KEY_SECRET") : (e.LICENSE_KEY_SECRET ?? "dev-only-license-key-secret");
  for (const [k, v] of [["CODE_HMAC_SECRET", secretCodes], ["LICENSE_KEY_SECRET", secretKeys]] as const) {
    if (strict && v && v.length < 32) problems.push(`${k} must be at least 32 characters`);
  }
  if (strict && /dev-only/.test(secretCodes + secretKeys)) problems.push("development secrets must not be used in staging/production");

  const paddle = { apiKey: "", webhookSecret: "", priceId: "" };
  if (providerName === "paddle") {
    paddle.apiKey = need("PADDLE_API_KEY");
    paddle.webhookSecret = need("PADDLE_WEBHOOK_SECRET");
    paddle.priceId = need("PADDLE_PRICE_ID");
  }
  const mockSecret = e.MOCK_WEBHOOK_SECRET ?? "dev-only-mock-webhook-secret";

  const from = e.EMAIL_FROM ?? "";
  const resendApiKey = e.RESEND_API_KEY ?? "";
  if (mailProvider === "resend") {
    if (!from) problems.push("EMAIL_FROM is required with EMAIL_PROVIDER=resend");
    if (!resendApiKey) problems.push("RESEND_API_KEY is required with EMAIL_PROVIDER=resend");
  }
  const allowedOrigins = (e.ALLOWED_ORIGINS ?? (strict ? "" : websiteUrl)).split(",").map((s) => s.trim()).filter(Boolean);
  if (strict && allowedOrigins.length === 0) problems.push("ALLOWED_ORIGINS is required");

  if (problems.length) throw new ConfigError(problems);

  let signingKey = privateKeyB64;
  if (!signingKey) {
    // development/test only: an ephemeral key (see `npm run dev:setup` for a persistent one)
    signingKey = crypto.generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  }
  return {
    env,
    port: int(e, "PORT", 8787),
    host: e.HOST ?? "127.0.0.1",
    websiteUrl,
    apiUrl,
    allowedOrigins,
    dbPath,
    trustProxy: e.TRUST_PROXY === "1",
    signing: { privateKeyB64: signingKey, kid: e.LICENSE_SIGNING_KID ?? "k1" },
    entitlementMode: providerName === "paddle" && paddleMode === "live" ? "live" : "test",
    secrets: { codes: secretCodes, licenseKeys: secretKeys },
    policy: {
      trialHours: int(e, "TRIAL_HOURS", 24),
      maxDevices: int(e, "MAX_DEVICES", 1),
      codeTtlSec: int(e, "CODE_TTL_SECONDS", 600),
      codeMaxAttempts: int(e, "CODE_MAX_ATTEMPTS", 5),
      offlineGraceDays: int(e, "OFFLINE_GRACE_DAYS", 30),
      codeCooldownSec: int(e, "CODE_COOLDOWN_SECONDS", 30),
      webhookToleranceSec: int(e, "WEBHOOK_TOLERANCE_SECONDS", 300),
    },
    rate: {
      codePerEmailHour: int(e, "RATE_CODE_PER_EMAIL_HOUR", 5),
      codePerIpHour: int(e, "RATE_CODE_PER_IP_HOUR", 20),
      codePerInstallationHour: int(e, "RATE_CODE_PER_INSTALLATION_HOUR", 10),
      verifyPerIpHour: int(e, "RATE_VERIFY_PER_IP_HOUR", 40),
      keyAttemptsPerIpHour: int(e, "RATE_KEY_ATTEMPTS_PER_IP_HOUR", 10),
    },
    provider: { name: providerName, mode: providerName === "mock" ? "mock" : paddleMode, mockWebhookSecret: mockSecret, paddle },
    mail: { provider: mailProvider, from, resendApiKey },
    identity: { name: identityName, googleClientId: e.GOOGLE_CLIENT_ID ?? "", googleClientSecret: e.GOOGLE_CLIENT_SECRET ?? "" },
    signinTtlSec: int(e, "SIGNIN_TTL_SECONDS", 600),
  };
}
