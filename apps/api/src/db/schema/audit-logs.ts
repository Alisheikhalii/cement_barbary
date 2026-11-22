import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  index,
  jsonb,
  pgTable,
  smallint,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { bytea, id } from './columns.js';
import { tenantId } from './tenants.js';
import { users } from './users.js';

/**
 * Append-only audit trail (ADR-009, F1-06 T04).
 *
 * `occurred_at` is forced by a BEFORE INSERT trigger (migration 0012): the
 * application cannot backdate a row. UPDATE/DELETE/TRUNCATE are rejected for
 * every role by triggers, and the runtime role has no such grants either.
 *
 * Snapshots (`before`/`after`) are produced by an allowlist in application
 * code — never a raw row — and PII inside them is masked. `ip_enc`/`ip_hash`
 * hold the encrypted client IP and its blind index; the raw IP is never stored
 * (owner CP1 Q2). The tenant always comes from the request context.
 */
export const auditLogs = pgTable(
  'audit_logs',
  {
    id: id(),
    tenantId: tenantId(),
    occurredAt: timestamp('occurred_at', { withTimezone: true, mode: 'date' })
      .notNull()
      .default(sql`clock_timestamp()`),
    /** 'user' (actor_user_id required) or 'system' (CLI/seed/worker). */
    actorType: varchar('actor_type', { length: 16 }).notNull(),
    actorUserId: uuid('actor_user_id'),
    actorSessionId: uuid('actor_session_id'),
    /** Stable action name, e.g. `user.role.assigned`. */
    action: varchar('action', { length: 64 }).notNull(),
    resourceType: varchar('resource_type', { length: 64 }).notNull(),
    resourceId: varchar('resource_id', { length: 128 }),
    outcome: varchar('outcome', { length: 16 }).notNull(),
    httpStatus: smallint('http_status'),
    reason: text('reason'),
    before: jsonb('before').$type<unknown>(),
    after: jsonb('after').$type<unknown>(),
    metadata: jsonb('metadata').$type<unknown>(),
    ipEnc: bytea('ip_enc'),
    ipHash: bytea('ip_hash'),
    requestId: varchar('request_id', { length: 64 }),
  },
  (t) => [
    check('audit_logs_actor_type_valid', sql`${t.actorType} in ('user', 'system')`),
    check(
      'audit_logs_actor_user_required',
      sql`(${t.actorType} = 'user') = (${t.actorUserId} is not null)`,
    ),
    check('audit_logs_action_format', sql`${t.action} ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$'`),
    check('audit_logs_outcome_valid', sql`${t.outcome} in ('success', 'failure', 'denied')`),
    check(
      'audit_logs_http_status_valid',
      sql`${t.httpStatus} is null or ${t.httpStatus} between 100 and 599`,
    ),
    check('audit_logs_reason_length', sql`${t.reason} is null or length(${t.reason}) <= 500`),
    // Exact logical cap (owner CP2): `pg_column_size` measures the compressed
    // on-disk form, so a highly compressible 100 KiB snapshot could pass. The
    // text form of a jsonb value is its logical payload and is not compressed.
    check(
      'audit_logs_before_size',
      sql`${t.before} is null or octet_length(${t.before}::text) <= 16384`,
    ),
    check(
      'audit_logs_after_size',
      sql`${t.after} is null or octet_length(${t.after}::text) <= 16384`,
    ),
    check(
      'audit_logs_metadata_size',
      sql`${t.metadata} is null or octet_length(${t.metadata}::text) <= 16384`,
    ),
    check('audit_logs_ip_pair', sql`(${t.ipEnc} is null) = (${t.ipHash} is null)`),
    // An append-only table can never delete a huge blob: cap the encrypted IP
    // and require the blind index to be exactly HMAC-SHA256 (32 bytes).
    check('audit_logs_ip_enc_size', sql`${t.ipEnc} is null or octet_length(${t.ipEnc}) <= 1024`),
    check('audit_logs_ip_hash_size', sql`${t.ipHash} is null or octet_length(${t.ipHash}) = 32`),
    foreignKey({
      columns: [t.tenantId, t.actorUserId],
      foreignColumns: [users.tenantId, users.id],
      name: 'audit_logs_actor_user_fk',
    }),
    index('audit_logs_tenant_occurred_idx').on(t.tenantId, t.occurredAt.desc()),
    index('audit_logs_tenant_actor_idx').on(t.tenantId, t.actorUserId, t.occurredAt),
    index('audit_logs_tenant_resource_idx').on(t.tenantId, t.resourceType, t.resourceId),
  ],
);
