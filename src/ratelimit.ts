import type { Db } from "./db.ts";

/** Persistent sliding-window limiter. Returns seconds until allowed again, or 0 if the action may proceed (and records it). */
export function hit(db: Db, bucket: string, limit: number, windowSec: number, now: number): number {
  db.prepare("DELETE FROM rate_events WHERE ts < ?").run(now - 86400);
  const rows = db.prepare("SELECT ts FROM rate_events WHERE bucket = ? AND ts > ? ORDER BY ts").all(bucket, now - windowSec) as { ts: number }[];
  if (rows.length >= limit) return Math.max(1, rows[0].ts + windowSec - now);
  db.prepare("INSERT INTO rate_events(bucket, ts) VALUES (?, ?)").run(bucket, now);
  return 0;
}
