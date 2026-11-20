import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  foreignKey,
  integer,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';

import { id, timestamps } from './columns.js';
import { tenantId } from './tenants.js';
import { users } from './users.js';

/**
 * One credential row per user (ADR-007 A1/A2/A19). Stores the Argon2id PHC
 * string only — never a plaintext password. The A2 progressive-delay counters
 * live here (per account, not in the rate-limit buckets). No DELETE for the
 * runtime role: rows are updated, never hard-deleted (users are soft-deleted).
 */
export const userCredentials = pgTable(
  'user_credentials',
  {
    id: id(),
    tenantId: tenantId(),
    userId: uuid('user_id').notNull(),
    /** Argon2id PHC string (A1) — enforced by the CHECK below. */
    passwordHash: text('password_hash').notNull(),
    /** A19: the operator-set first password is one-time; true until the user changes it. */
    mustChangePassword: boolean('must_change_password').notNull().default(true),
    /** A2: consecutive failures drive the progressive delay; reset on success. */
    failedAttempts: integer('failed_attempts').notNull().default(0),
    /** A2: before this moment, attempts get the generic 401 without a verify. */
    nextAttemptAt: timestamp('next_attempt_at', { withTimezone: true, mode: 'date' }),
    /** A19: one-time passwords die here; NULL once a real password is set. */
    temporaryPasswordExpiresAt: timestamp('temporary_password_expires_at', {
      withTimezone: true,
      mode: 'date',
    }),
    ...timestamps,
  },
  (t) => [
    check('user_credentials_phc_format', sql`${t.passwordHash} LIKE '$argon2id$%'`),
    check('user_credentials_failed_attempts_nonneg', sql`${t.failedAttempts} >= 0`),
    // A19: a one-time password (expiry set) always forces a change; clearing
    // the flag therefore requires clearing the expiry (single use).
    check(
      'user_credentials_temp_pw_forces_change',
      sql`${t.temporaryPasswordExpiresAt} is null or ${t.mustChangePassword}`,
    ),
    // One credential row per user; the unique index also leads with tenant_id.
    unique('user_credentials_tenant_user_uq').on(t.tenantId, t.userId),
    // ADR-006 U5 pattern: a credential can never point at another tenant's user.
    foreignKey({
      columns: [t.tenantId, t.userId],
      foreignColumns: [users.tenantId, users.id],
      name: 'user_credentials_user_fk',
    }),
  ],
);
