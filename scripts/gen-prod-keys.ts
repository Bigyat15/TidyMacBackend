// Prints a NEW Ed25519 license signing key pair. Store the private key in your secret manager (never in git).
import { generateKeyPair } from "../src/crypto.ts";

const k = generateKeyPair();
console.log("LICENSE_SIGNING_PRIVATE_KEY=" + k.privateKeyB64);
console.log("# Public key (embed in the app build as TIDYMAC_LICENSE_PUBKEY):");
console.log("TIDYMAC_LICENSE_PUBKEY=" + k.publicKeyB64);
console.error("\nBack up the private key. If it is lost, every installed app must be updated with a new public key.");
