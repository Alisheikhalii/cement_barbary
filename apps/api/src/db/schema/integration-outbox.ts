import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  index,
  integer,
  pgTable,
  timestamp,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { bytea, id } from './columns.js';
import { tenantId, tenants } from './tenants.js';

/**
 * Transactional outbox (ADR-010 L12–L14, F1-06 T08).
 *
 * A business change and its outgoing message commit together: `OutboxWriter`
 * inserts here in the caller's transaction, encrypted (payloads may carry a
 * phone number). The unique `(tenant_id, topic, dedupe_key)` makes a duplicate
 * enqueue a no-op. Delivery is at-least-once with NO global ordering guarantee
 * (ADR-010): rows are claimed due-first but workers may run concurrently and
 * retries move a row back in time.
 *
 * State machine:
 *   pending → processing (claim, attempts+1, lease token)
 *   processing → sent (CAS on lock_token) | pending (backoff) | dead (max)
 *   processing with an expired lease → reclaimed; if attempts >= max_attempts
 *   a pre-claim sweep moves it to `dead` (never increments past max).
 */
export const integrationOutbox = pgTable(
  'integration_outbox',
  {
    id: id(),
    tenantId: tenantId(),
    /** Stable topic, e.g. `sms.otp` / `mock.echo`. */
    topic: varchar('topic', { length: 64 }).notNull(),
    /** Producer-chosen idempotency key inside (tenant, topic). */
    dedupeKey: varchar('dedupe_key', { length: 128 }).notNull(),
    payloadEnc: bytea('payload_enc').notNull(),
    status: varchar('status', { length: 16 }).notNull().default('pending'),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(5),
    nextAttemptAt: timestamp('next_attempt_at', { withTimezone: true, mode: 'date' })
      .notNull()
      .defaultNow(),
    lockedUntil: timestamp('locked_until', { withTimezone: true, mode: 'date' }),
    lockToken: uuid('lock_token'),
    /** Sanitized code only — never provider text or a payload value. */
    lastErrorCode: varchar('last_error_code', { length: 64 }),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow(),
    sentAt: timestamp('sent_at', { withTimezone: true, mode: 'date' }),
  },
  (t) => [
    check(
      'integration_outbox_status_valid',
      sql`${t.status} in ('pending', 'processing', 'sent', 'dead')`,
    ),
    check('integration_outbox_topic_format', sql`${t.topic} ~ '^[a-z][a-z0-9_.]{2,63}$'`),
    check('integration_outbox_dedupe_format', sql`${t.dedupeKey} ~ '^[A-Za-z0-9_.:-]{1,128}$'`),
    check('integration_outbox_payload_size', sql`octet_length(${t.payloadEnc}) <= 65600`),
    check(
      'integration_outbox_attempts_range',
      // `pending` never sits at the ceiling (that would be a permanent zombie:
      // the claim refuses it and the sweep only scans `processing`). `processing`
      // may be at the ceiling — that is the final allowed attempt.
      sql`${t.attempts} between 0 and ${t.maxAttempts} and ${t.maxAttempts} between 1 and 20 and (${t.status} <> 'pending' or ${t.attempts} < ${t.maxAttempts})`,
    ),
    // A processing row always carries its lease; every other state carries none.
    check(
      'integration_outbox_lease_pair',
      sql`(${t.status} = 'processing') = (${t.lockedUntil} is not null and ${t.lockToken} is not null)`,
    ),
    check(
      'integration_outbox_sent_at_valid',
      sql`(${t.status} = 'sent') = (${t.sentAt} is not null)`,
    ),
    unique('integration_outbox_scope_uq').on(t.tenantId, t.topic, t.dedupeKey),
    foreignKey({
      columns: [t.tenantId],
      foreignColumns: [tenants.id],
      name: 'integration_outbox_tenant_id_tenants_id_fk',
    }).onDelete('restrict'),
    index('integration_outbox_due_idx')
      .on(t.tenantId, t.nextAttemptAt)
      .where(sql`${t.status} in ('pending', 'processing')`),
    index('integration_outbox_tenant_status_idx').on(t.tenantId, t.status),
  ],
);
