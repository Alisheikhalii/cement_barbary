import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  index,
  inet,
  pgTable,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { bytea, id, timestamps } from './columns.js';
import { tenantId } from './tenants.js';
import { users } from './users.js';

/**
 * Refresh-token sessions (ADR-007 A8–A10). Only SHA-256 hashes of refresh
 * tokens are stored — never a token. Soft-revoke only (`revoked_at`); the
 * runtime role gets no DELETE (purge of expired rows is recorded debt, run as
 * the owner). Rotation: `refresh_hash` holds the CURRENT token's hash; the
 * previous one moves to `previous_refresh_hash`, so replaying a rotated-out
 * token is detected and revokes the whole family (A8).
 */
export const authSessions = pgTable(
  'auth_sessions',
  {
    id: id(),
    tenantId: tenantId(),
    userId: uuid('user_id').notNull(),
    /** A8: all tokens of one login chain share a family; reuse revokes it whole. */
    familyId: uuid('family_id').notNull(),
    /** SHA-256 of the current refresh token (32 bytes). */
    refreshHash: bytea('refresh_hash').notNull(),
    /** The rotated-out token's hash — a second presentation of it is reuse (A8). */
    previousRefreshHash: bytea('previous_refresh_hash'),
    ip: inet('ip'),
    userAgent: varchar('user_agent', { length: 512 }),
    /** Session death = refresh-token lifetime (A8: 30 days). */
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
    rotatedAt: timestamp('rotated_at', { withTimezone: true, mode: 'date' }),
    revokedAt: timestamp('revoked_at', { withTimezone: true, mode: 'date' }),
    /** A9: last successful refresh (idle tracking ops aid). */
    lastUsedAt: timestamp('last_used_at', { withTimezone: true, mode: 'date' }),
    /** A9: why the session was revoked ('logout', 'reuse_detected', 'sibling', 'password_change', 'disabled'). */
    revokeReason: varchar('revoke_reason', { length: 32 }),
    ...timestamps,
  },
  (t) => [
    // Global uniqueness: the refresh lookup at T05 finds a session by hash.
    uniqueIndex('auth_sessions_refresh_hash_uq').on(t.refreshHash),
    // BR-18 / A19: revoke a user's sessions (both lead with tenant_id).
    index('auth_sessions_tenant_user_idx').on(t.tenantId, t.userId),
    // A8: family revocation.
    index('auth_sessions_tenant_family_idx').on(t.tenantId, t.familyId),
    // Reuse detection: the session lookup matches current OR previous hash —
    // without this index the OR forces a scan (re-review LOW, pre-T05 traffic).
    index('auth_sessions_previous_refresh_hash_idx').on(t.previousRefreshHash),
    check(
      'auth_sessions_previous_rotated',
      sql`${t.previousRefreshHash} is null or ${t.rotatedAt} is not null`,
    ),
    foreignKey({
      columns: [t.tenantId, t.userId],
      foreignColumns: [users.tenantId, users.id],
      name: 'auth_sessions_user_fk',
    }),
  ],
);
