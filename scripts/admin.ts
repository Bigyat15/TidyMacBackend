// Operator CLI. Runs against the database directly (there are deliberately NO public admin endpoints).
//   node scripts/admin.ts show <email>
//   node scripts/admin.ts revoke-license <license_id> <reason>
//   node scripts/admin.ts delete-customer <email>
import { openDb } from "../src/db.ts";
import { maskEmail } from "../src/mail.ts";

const [cmd, a, b] = process.argv.slice(2);
const dbPath = process.env.DATABASE_PATH;
if (!dbPath || dbPath === ":memory:") { console.error("Set DATABASE_PATH to the licensing database file."); process.exit(2); }
const db = openDb(dbPath);
const now = Math.floor(Date.now() / 1000);

if (cmd === "show" && a) {
  const c = db.prepare("SELECT * FROM customers WHERE email = ?").get(a.toLowerCase()) as any;
  if (!c) { console.log("no such customer"); process.exit(0); }
  console.log({ customer: c.id, email: maskEmail(c.email) });
  console.log("trial:", db.prepare("SELECT started_at, expires_at FROM trials WHERE customer_id = ?").get(c.id));
  console.log("licenses:", db.prepare("SELECT id, status, simulated, max_devices, revoke_reason FROM licenses WHERE customer_id = ?").all(c.id));
  console.log("purchases:", db.prepare("SELECT id, provider, provider_order_id, status, simulated FROM purchases WHERE customer_id = ?").all(c.id));
} else if (cmd === "revoke-license" && a && b) {
  const r = db.prepare("UPDATE licenses SET status = 'revoked', revoked_at = ?, revoke_reason = ? WHERE id = ? AND status = 'active'").run(now, b, a);
  db.prepare("INSERT INTO audit_events(ts, type, meta) VALUES (?, 'license_revoked_manual', ?)").run(now, JSON.stringify({ license: a, reason: b }));
  console.log(r.changes ? "revoked (the app notices at its next refresh)" : "nothing changed");
} else if (cmd === "delete-customer" && a) {
  // Removes personal data but keeps purchase/tax records (legally required) with the email anonymized.
  const c = db.prepare("SELECT id FROM customers WHERE email = ?").get(a.toLowerCase()) as any;
  if (!c) { console.log("no such customer"); process.exit(0); }
  db.exec("BEGIN IMMEDIATE");
  db.prepare("UPDATE customers SET email = ?, deleted_at = ? WHERE id = ?").run(`deleted-${c.id}@invalid`, now, c.id);
  db.prepare("DELETE FROM email_codes WHERE email = ?").run(a.toLowerCase());
  db.prepare("UPDATE activations SET active = 0, device_name = 'deleted' WHERE trial_id IN (SELECT id FROM trials WHERE customer_id = ?) OR license_id IN (SELECT id FROM licenses WHERE customer_id = ?)").run(c.id, c.id);
  db.prepare("INSERT INTO audit_events(ts, type, customer_id, meta) VALUES (?, 'customer_data_deleted', ?, '{}')").run(now, c.id);
  db.exec("COMMIT");
  console.log("personal data removed; purchase records retained with an anonymized email. NOTE: the trial record stays so the trial cannot be reused.");
} else {
  console.log("usage: show <email> | revoke-license <license_id> <reason> | delete-customer <email>");
}
