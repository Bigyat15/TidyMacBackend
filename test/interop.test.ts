// @vitest-environment node
// Cross-language contract: the exact token bytes the Node server signs must verify in the Rust app
// (src-tauri/src/licensing/token.rs reads the same fixture). Ed25519 is deterministic, so the fixture is reproducible.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { publicKeyOf, signEntitlement, verifyEntitlement, type EntitlementPayload } from "../src/crypto.ts";

const SEED = Buffer.alloc(32, 0x2a); // a public, throwaway TEST key; never used outside tests
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKeyB64 = Buffer.concat([PKCS8_PREFIX, SEED]).toString("base64");
const FIXTURE = path.join(import.meta.dirname, "fixtures", "interop.json");

const base: Omit<EntitlementPayload, "kind" | "expires_at" | "started_at" | "license" | "check_by"> = {
  v: 1, product: "tidymac", mode: "live", ent_id: "ent_interop", customer: "cus_interop", installation: "install-interop-0001",
  activation: "act_interop", issued_at: 1_800_000_000, updates_through_major: 1, kid: "k1",
};
const trial: EntitlementPayload = { ...base, kind: "trial", started_at: 1_800_000_000, expires_at: 1_800_000_000 + 86400, license: null, check_by: 1_800_000_000 + 86400 };
const pro: EntitlementPayload = { ...base, kind: "pro", started_at: null, expires_at: null, license: "lic_interop", check_by: 1_800_000_000 + 30 * 86400 };

describe("node <-> rust token contract", () => {
  const fixture = {
    public_key: publicKeyOf(privateKeyB64),
    trial: { token: signEntitlement(privateKeyB64, trial), payload: trial },
    pro: { token: signEntitlement(privateKeyB64, pro), payload: pro },
  };
  it("fixture file matches what the server code signs today", () => {
    if (process.env.UPDATE_FIXTURE === "1") fs.writeFileSync(FIXTURE, JSON.stringify(fixture, null, 2) + "\n");
    expect(JSON.parse(fs.readFileSync(FIXTURE, "utf8"))).toEqual(fixture);
  });
  it("verifies on the server side too", () => {
    expect(verifyEntitlement(fixture.public_key, fixture.trial.token)).toEqual(trial);
    expect(verifyEntitlement(fixture.public_key, fixture.pro.token)).toEqual(pro);
  });
});
