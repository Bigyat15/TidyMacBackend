import type { Db } from "./db.ts";

/** Data-retention job (run daily from cron/scheduler: `node scripts/prune.ts`). Matches the published privacy policy. */
export const RETENTION = { codesDays: 7, manageTokensDays: 1, auditDays: 400, rateEventsDays: 1 };

export function prune(db: Db, now: number) {
  const day = 86400;
  const run = (sql: string, ...p: number[]) => Number(db.prepare(sql).run(...p).changes);
  return {
    codes: run("DELETE FROM email_codes WHERE created_at < ?", now - RETENTION.codesDays * day),
    manageTokens: run("DELETE FROM manage_tokens WHERE expires_at < ?", now - RETENTION.manageTokensDays * day),
    audit: run("DELETE FROM audit_events WHERE ts < ?", now - RETENTION.auditDays * day),
    rateEvents: run("DELETE FROM rate_events WHERE ts < ?", now - RETENTION.rateEventsDays * day),
  };
}
