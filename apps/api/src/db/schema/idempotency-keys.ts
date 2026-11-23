import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  index,
  pgTable,
  smallint,
  timestamp,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { bytea, id } from './columns.js';
import { tenantId } from './tenants.js';
import { users } from './users.js';

/**
 * Idempotency claims and stored responses (ADR-010 L8/L9/L11, F1-06 T07).
 *
 * A row is claimed with `INSERT … ON CONFLICT DO NOTHING` inside the SAME
 * transaction as the handler, then marked `completed` with the encrypted
 * response before that transaction commits. Consequences:
 *  - a crash or rollback leaves no row, so a retry executes again;
 *  - `in_progress` can only be observed by a concurrent duplicate (the unique
 *    key blocks it), never by a later request;
 *  - only SUCCESSFUL responses are stored (owner CP4 change 5): any thrown
 *    error — including a business 4xx — rolls back, and a retry re-executes;
 *  - an expired row is taken over by a CAS update (`expires_at < now()`), still
 *    with exactly one executing handler;
 *  - `response_enc` is AES-GCM with AAD `tenant:idempotency_keys.response_enc:<rowId>`,
 *    so a blob moved to another row/tenant cannot be decrypted.
 *
 * The runtime role may DELETE only expired rows (RESTRICTIVE policy in 0014),
 * so a live claim or stored body can never be removed by the application.
 */
export const idempotencyKeys = pgTable(
  'idempotency_keys',
  {
    id: id(),
    tenantId: tenantId(),
    userId: uuid('user_id').notNull(),
    /** `METHOD + " " + route template`, never the raw URL. */
    routeKey: varchar('route_key', { length: 160 }).notNull(),
    idemKey: varchar('idem_key', { length: 128 }).notNull(),
    /** SHA-256 over canonical `{params, query, body}` — exactly 32 bytes. */
    fingerprint: bytea('fingerprint').notNull(),
    status: varchar('status', { length: 16 }).notNull().default('in_progress'),
    responseStatus: smallint('response_status'),
    responseEnc: bytea('response_enc'),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
  },
  (t) => [
    check('idempotency_keys_status_valid', sql`${t.status} in ('in_progress', 'completed')`),
    check('idempotency_keys_key_format', sql`${t.idemKey} ~ '^[A-Za-z0-9_-]{16,128}$'`),
    check(
      'idempotency_keys_route_format',
      sql`${t.routeKey} ~ '^[A-Z]{3,7} /[A-Za-z0-9_:/{}.@-]{1,150}$'`,
    ),
    check('idempotency_keys_fingerprint_size', sql`octet_length(${t.fingerprint}) = 32`),
    // A completed row always carries both response fields; an in-progress row
    // carries neither. Both halves are explicit: the simple `A = (X and Y)`
    // form would still admit `in_progress` with exactly one field set.
    check(
      'idempotency_keys_completed_fields',
      sql`(${t.status} = 'completed' and ${t.responseStatus} is not null and ${t.responseEnc} is not null)
        or (${t.status} <> 'completed' and ${t.responseStatus} is null and ${t.responseEnc} is null)`,
    ),
    check(
      'idempotency_keys_response_status_valid',
      sql`${t.responseStatus} is null or ${t.responseStatus} between 100 and 599`,
    ),
    // 30-byte PII header + 64 KiB plaintext cap + margin.
    check(
      'idempotency_keys_response_size',
      sql`${t.responseEnc} is null or octet_length(${t.responseEnc}) <= 65600`,
    ),
    check('idempotency_keys_expiry_order', sql`${t.expiresAt} > ${t.createdAt}`),
    unique('idempotency_keys_scope_uq').on(t.tenantId, t.userId, t.routeKey, t.idemKey),
    foreignKey({
      columns: [t.tenantId, t.userId],
      foreignColumns: [users.tenantId, users.id],
      name: 'idempotency_keys_user_fk',
    }),
    index('idempotency_keys_tenant_expiry_idx').on(t.tenantId, t.expiresAt),
  ],
);
