import crypto from "node:crypto";

const DOMAIN = Buffer.from("tidymac-entitlement-v1\0");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const sha256hex = (s: string | Buffer) => crypto.createHash("sha256").update(s).digest("hex");
export const hmacHex = (secret: string, ...parts: string[]) => crypto.createHmac("sha256", secret).update(parts.join("\0")).digest("hex");
export const randomId = (prefix: string) => `${prefix}_${crypto.randomBytes(12).toString("base64url")}`;

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

export function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKeyB64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    publicKeyB64: (publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(SPKI_ED25519_PREFIX.length).toString("base64"),
  };
}

export function publicKeyOf(privateKeyB64: string): string {
  const priv = crypto.createPrivateKey({ key: Buffer.from(privateKeyB64, "base64"), format: "der", type: "pkcs8" });
  return (crypto.createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer).subarray(SPKI_ED25519_PREFIX.length).toString("base64");
}

export interface EntitlementPayload {
  v: 1;
  product: "tidymac";
  kind: "trial" | "pro";
  mode: "test" | "live";
  ent_id: string;
  customer: string;
  installation: string;
  activation: string;
  license: string | null;
  issued_at: number;
  /** Trials only: when the 24-hour clock started (server time). */
  started_at: number | null;
  expires_at: number | null;
  check_by: number;
  updates_through_major: number;
  kid: string;
}

/** `TM1.<base64url payload>.<base64url Ed25519 signature>`, signed over a domain-separation prefix + the exact payload bytes. */
export function signEntitlement(privateKeyB64: string, payload: EntitlementPayload): string {
  const priv = crypto.createPrivateKey({ key: Buffer.from(privateKeyB64, "base64"), format: "der", type: "pkcs8" });
  const body = Buffer.from(JSON.stringify(payload));
  const sig = crypto.sign(null, Buffer.concat([DOMAIN, body]), priv);
  return `TM1.${body.toString("base64url")}.${sig.toString("base64url")}`;
}

export function verifyEntitlement(publicKeyB64: string, token: string): EntitlementPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "TM1") return null;
  try {
    const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyB64, "base64")]), format: "der", type: "spki" });
    const body = Buffer.from(parts[1], "base64url");
    if (!crypto.verify(null, Buffer.concat([DOMAIN, body]), pub, Buffer.from(parts[2], "base64url"))) return null;
    const p = JSON.parse(body.toString()) as EntitlementPayload;
    return p.v === 1 && p.product === "tidymac" ? p : null;
  } catch {
    return null;
  }
}

// License keys: 20 unambiguous characters, shown as TM-XXXXX-XXXXX-XXXXX-XXXXX.
const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
export function generateLicenseKey(): string {
  let s = "";
  for (let i = 0; i < 20; i++) s += ALPHABET[crypto.randomInt(ALPHABET.length)];
  return `TM-${s.match(/.{5}/g)!.join("-")}`;
}
export function normalizeLicenseKey(k: string): string | null {
  const s = k.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^TM/, "");
  return s.length === 20 && [...s].every((c) => ALPHABET.includes(c)) ? `TM-${s.match(/.{5}/g)!.join("-")}` : null;
}

// Reversible encryption so a verified customer can be re-sent their key (AES-256-GCM, key derived with HKDF).
const aesKey = (secret: string) => Buffer.from(crypto.hkdfSync("sha256", secret, "tidymac", "license-key-encryption", 32));
export function encryptSecret(secret: string, plain: string): string {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aesKey(secret), iv);
  const enc = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString("base64");
}
export function decryptSecret(secret: string, blob: string): string {
  const b = Buffer.from(blob, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", aesKey(secret), b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
}
