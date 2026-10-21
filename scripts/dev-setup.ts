// Creates a development signing key + secrets in .dev/ (gitignored) and prints the PUBLIC key.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { generateKeyPair } from "../src/crypto.ts";

const dir = path.join(import.meta.dirname, "..", ".dev");
fs.mkdirSync(dir, { recursive: true });
const envFile = path.join(dir, "dev.env");
if (fs.existsSync(envFile)) {
  console.log(".dev/dev.env already exists; keeping it. Delete it to regenerate (installed dev builds will then need the new public key).");
} else {
  const k = generateKeyPair();
  const rnd = () => crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(envFile, [
    "# Development only. Never reuse these values in staging or production.",
    `LICENSE_SIGNING_PRIVATE_KEY=${k.privateKeyB64}`,
    `LICENSE_PUBLIC_KEY=${k.publicKeyB64}`,
    `CODE_HMAC_SECRET=dev-only-${rnd()}`,
    `LICENSE_KEY_SECRET=dev-only-${rnd()}`,
    "DATABASE_PATH=" + path.join(dir, "dev.sqlite"),
    "",
  ].join("\n"), { mode: 0o600 });
}
const pub = fs.readFileSync(envFile, "utf8").match(/^LICENSE_PUBLIC_KEY=(.*)$/m)![1];
console.log("Dev license public key: " + pub + "\nStart the API with: npm run dev");
