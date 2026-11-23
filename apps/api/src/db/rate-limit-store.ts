import { Inject, Injectable } from '@nestjs/common';
import { sql } from 'drizzle-orm';

import { DB, type Db } from './database.providers.js';

/**
 * Atomic fixed-window counters for `auth_rate_limits` (ADR-007 A11). Lives
 * inside src/db/** because it needs raw SQL: a single upsert both starts a new
 * window and increments an open one, so concurrent callers can never
 * lost-update each other. The table is global (U14 allowlist, no tenant_id).
 */

export interface RateLimitHit {
  readonly count: number;
  /** Window close, normalized to a Date (raw execute keeps timestamps as strings). */
  readonly expiresAt: Date;
  /**
   * Whole seconds until the window closes, computed by PostgreSQL in the same
   * statement/transaction as `expires_at`. Callers never subtract a Node clock
   * from a DB timestamp (that cross-clock math was the 429 boundary flake).
   */
  readonly retryAfterSeconds: number;
}

@Injectable()
export class RateLimitStore {
  constructor(@Inject(DB) private readonly db: Db) {}

  /**
   * Increments the counter for `key`, starting a new window when the old one
   * expired.
   *
   * F1-07 T01: the upsert runs in its own short transaction with
   * `synchronous_commit = off` (same pattern as `CredentialFailureStore`). A
   * rate-limit counter is best-effort anti-brute-force state, so skipping the
   * WAL flush does not change counting order, atomicity or lockout accuracy —
   * it only lets the row lock go without waiting for fsync. Without this, 50
   * simultaneous hits on one bucket serialize behind 50 commits and the last
   * waiters can exceed the 5 s statement timeout (57014). Apart from the A2
   * delay counter, which uses the same setting, every other write keeps full
   * durability.
   */
  async hit(key: string, windowSeconds: number): Promise<RateLimitHit> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`set local synchronous_commit = off`);
      const result = await tx.execute<{
        count: number;
        expires_at: Date | string;
        retry_after_seconds: number | string;
      }>(sql`
        INSERT INTO auth_rate_limits (key, count, expires_at)
        VALUES (${key}, 1, now() + make_interval(secs => ${windowSeconds}))
        ON CONFLICT (key) DO UPDATE SET
          count = CASE
            WHEN auth_rate_limits.expires_at <= now() THEN 1
            ELSE auth_rate_limits.count + 1
          END,
          expires_at = CASE
            WHEN auth_rate_limits.expires_at <= now() THEN now() + make_interval(secs => ${windowSeconds})
            ELSE auth_rate_limits.expires_at
          END
        RETURNING count, expires_at,
          GREATEST(1, CEIL(EXTRACT(EPOCH FROM (expires_at - now()))))::int
            AS retry_after_seconds
      `);
      const row = result.rows[0];
      if (!row) {
        // A RETURNING-less upsert cannot happen; treat it as a closed door.
        return {
          count: Number.MAX_SAFE_INTEGER,
          expiresAt: new Date(Date.now() + 60_000),
          retryAfterSeconds: windowSeconds,
        };
      }
      return {
        count: Number(row.count),
        expiresAt: row.expires_at instanceof Date ? row.expires_at : new Date(row.expires_at),
        retryAfterSeconds: Number(row.retry_after_seconds),
      };
    });
  }

  /** Deletes closed windows. Runs hourly from the limiter plus on demand in tests. */
  async sweep(): Promise<number> {
    const result = await this.db.execute(
      sql`DELETE FROM auth_rate_limits WHERE expires_at <= now()`,
    );
    return result.rowCount ?? 0;
  }
}
