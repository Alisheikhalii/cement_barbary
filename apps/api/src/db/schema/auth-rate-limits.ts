import { sql } from 'drizzle-orm';
import { check, index, integer, pgTable, text, timestamp } from 'drizzle-orm/pg-core';

/**
 * Global fixed-window rate-limit counters (ADR-007 A11). NO tenant_id by
 * design — the bucket is inside the key (`login:ip:…`, `login:tenant:…`), so
 * the RLS template cannot apply; the table sits on the U14 allowlist with the
 * written reason "security counters, no tenant ownership, no PII" (A16).
 * Expired rows are removed lazily on read and by the hourly sweep — the
 * runtime role keeps DELETE on this table only.
 */
export const authRateLimits = pgTable(
  'auth_rate_limits',
  {
    /** Bucket key built by `rateLimitKeys` (e.g. `login:ip:203.0.113.7`). */
    key: text('key').primaryKey(),
    count: integer('count').notNull().default(0),
    /** Fixed-window end; past this, the next hit starts a fresh window. */
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
  },
  (t) => [
    check('auth_rate_limits_count_nonneg', sql`${t.count} >= 0`),
    index('auth_rate_limits_expires_idx').on(t.expiresAt),
  ],
);
