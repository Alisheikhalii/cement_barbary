import { sql } from 'drizzle-orm';
import { check, foreignKey, pgTable, unique, uniqueIndex, varchar } from 'drizzle-orm/pg-core';

import { bytea, createdBy, deletedAt, id, timestamps } from './columns.js';
import { tenantId } from './tenants.js';

/**
 * One person = one user row per tenant (ADR-006 U3, U12). Phone and national
 * ID are never stored in plaintext — only the AES-256-GCM blob (U7) and the
 * HMAC blind index (U8). The national-ID columns exist now but stay EMPTY for
 * the whole phase (owner Q3): no code path may write to them in F1-03.
 *
 * Soft delete only (U13): DELETE is revoked from the runtime role in T04.
 */
export const users = pgTable(
  'users',
  {
    id: id(),
    tenantId: tenantId(),
    /** Optional login name; unique per tenant while the row is alive. */
    username: varchar('username', { length: 32 }),
    displayName: varchar('display_name', { length: 200 }).notNull(),
    status: varchar('status', { length: 16 }).notNull().default('active'),
    phoneEnc: bytea('phone_enc'),
    phoneHash: bytea('phone_hash'),
    nationalIdEnc: bytea('national_id_enc'),
    nationalIdHash: bytea('national_id_hash'),
    ...timestamps,
    createdBy: createdBy(),
    deletedAt: deletedAt(),
  },
  (t) => [
    // U12: a user must be reachable by username or by phone.
    check('users_login_present', sql`${t.username} is not null or ${t.phoneHash} is not null`),
    check('users_username_format', sql`${t.username} ~ '^[a-z0-9._-]{3,32}$'`),
    check('users_status_valid', sql`${t.status} in ('active', 'disabled')`),
    // U12: each _enc is NULL exactly when its _hash is NULL (a blind index
    // without the ciphertext would be an orphaned capability).
    check('users_phone_pair', sql`(${t.phoneEnc} is null) = (${t.phoneHash} is null)`),
    check(
      'users_national_id_pair',
      sql`(${t.nationalIdEnc} is null) = (${t.nationalIdHash} is null)`,
    ),
    // Uniqueness is per tenant, never global (U8, change (d)); partial, so
    // soft-deleted rows do not block reuse. All three lead with tenant_id.
    uniqueIndex('users_tenant_username_uq')
      .on(t.tenantId, t.username)
      .where(sql`${t.deletedAt} is null`),
    uniqueIndex('users_tenant_phone_uq')
      .on(t.tenantId, t.phoneHash)
      .where(sql`${t.deletedAt} is null`),
    uniqueIndex('users_tenant_national_id_uq')
      .on(t.tenantId, t.nationalIdHash)
      .where(sql`${t.deletedAt} is null`),
    // Target of the composite FKs in U5 (user_roles) and U6 (created_by). A
    // UNIQUE CONSTRAINT (not a unique index) so it exists inside CREATE TABLE,
    // before the ALTER TABLE statements that add the FKs.
    unique('users_tenant_id_uq').on(t.tenantId, t.id),
    // U6: who created the row, same tenant only; NULL for seed/CLI actors.
    foreignKey({
      columns: [t.tenantId, t.createdBy],
      foreignColumns: [t.tenantId, t.id],
      name: 'users_created_by_fk',
    }),
  ],
);
