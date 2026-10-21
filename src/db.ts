import { DatabaseSync } from "node:sqlite";

const MIGRATIONS: string[] = [
  `
  CREATE TABLE customers (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    email_verified_at INTEGER,
    created_at INTEGER NOT NULL,
    deleted_at INTEGER
  );
  CREATE TABLE email_codes (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    code_hmac TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    consumed_at INTEGER
  );
  CREATE INDEX idx_email_codes_lookup ON email_codes(email, purpose, created_at);
  CREATE TABLE trials (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL UNIQUE REFERENCES customers(id),
    started_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE checkouts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_ref TEXT,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'created',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE purchases (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_order_id TEXT NOT NULL,
    customer_id TEXT REFERENCES customers(id),
    checkout_id TEXT REFERENCES checkouts(id),
    status TEXT NOT NULL,
    price_id TEXT,
    currency TEXT,
    amount_minor INTEGER,
    simulated INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (provider, provider_order_id)
  );
  CREATE TABLE licenses (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    purchase_id TEXT NOT NULL UNIQUE REFERENCES purchases(id),
    key_hmac TEXT NOT NULL UNIQUE,
    key_enc TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    max_devices INTEGER NOT NULL,
    simulated INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoke_reason TEXT
  );
  CREATE INDEX idx_licenses_customer ON licenses(customer_id);
  CREATE TABLE activations (
    id TEXT PRIMARY KEY,
    trial_id TEXT REFERENCES trials(id),
    license_id TEXT REFERENCES licenses(id),
    installation_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    deactivated_at INTEGER,
    CHECK ((trial_id IS NULL) <> (license_id IS NULL))
  );
  CREATE UNIQUE INDEX idx_activations_owner_install ON activations(COALESCE(trial_id, license_id), installation_id);
  CREATE TABLE manage_tokens (
    id TEXT PRIMARY KEY,
    token_hmac TEXT NOT NULL UNIQUE,
    customer_id TEXT NOT NULL,
    trial_id TEXT,
    license_id TEXT,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
  );
  CREATE TABLE webhook_events (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    state TEXT NOT NULL,
    error TEXT,
    payload_sha256 TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    processed_at INTEGER,
    UNIQUE (provider, event_id)
  );
  CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    type TEXT NOT NULL,
    customer_id TEXT,
    meta TEXT
  );
  CREATE INDEX idx_audit_type_ts ON audit_events(type, ts);
  CREATE TABLE rate_events (
    bucket TEXT NOT NULL,
    ts INTEGER NOT NULL
  );
  CREATE INDEX idx_rate_events ON rate_events(bucket, ts);
  `,
  `
  -- canonical identity: a.b+x@gmail.com and ab@gmail.com are one person (one trial)
  ALTER TABLE customers ADD COLUMN canon TEXT;
  UPDATE customers SET canon = email;
  CREATE INDEX idx_customers_canon ON customers(canon);
  CREATE TABLE login_sessions (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    challenge TEXT NOT NULL,
    state_hmac TEXT,
    nonce TEXT,
    pkce_verifier TEXT,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | begun | authenticated | denied | consumed
    customer_id TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX idx_login_state ON login_sessions(state_hmac);
  `,
];

export type Db = DatabaseSync;

export function openDb(path: string): Db {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  if (path !== ":memory:") db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;");
  migrate(db);
  return db;
}

export function migrate(db: Db) {
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)");
  const current = (db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number }).v;
  if (current > MIGRATIONS.length) throw new Error(`database schema v${current} is newer than this server (v${MIGRATIONS.length})`);
  for (let i = current; i < MIGRATIONS.length; i++) {
    db.exec("BEGIN IMMEDIATE");
    try {
      db.exec(MIGRATIONS[i]);
      db.prepare("INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)").run(i + 1, Math.floor(Date.now() / 1000));
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }
}

/** Runs `fn` in an immediate transaction (no awaits inside!). */
export function tx<T>(db: Db, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const r = fn();
    db.exec("COMMIT");
    return r;
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}
