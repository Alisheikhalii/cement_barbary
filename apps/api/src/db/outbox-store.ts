import { Inject, Injectable } from '@nestjs/common';
import { sql } from 'drizzle-orm';

import { DB, type Db } from './database.providers.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantDb as the constructor param type for DI
import { TenantDb } from './tenant-db.js';

/**
 * The only SQL path to `integration_outbox` (ADR-010 L12–L14, F1-06 T08).
 *
 * Producer writes and worker state changes go through `TenantDb.run`, so an
 * enqueue joins the caller's business transaction and every worker step is
 * tenant-scoped by RLS. Claims use `FOR UPDATE SKIP LOCKED`; marking uses a
 * `(id, lock_token)` CAS so an expired lease can never be overwritten.
 */

export interface OutboxInsert {
  readonly id: string;
  readonly tenantId: string;
  readonly topic: string;
  readonly dedupeKey: string;
  readonly payloadEnc: Buffer;
  readonly maxAttempts: number;
}

export interface ClaimedOutboxRow {
  readonly id: string;
  readonly topic: string;
  readonly payloadEnc: Buffer;
  readonly attempts: number;
  readonly maxAttempts: number;
  readonly lockToken: string;
}

export interface DeadOutboxRow {
  readonly id: string;
  readonly topic: string;
}

interface ClaimRow {
  readonly id: string;
  readonly topic: string;
  readonly payload_enc: Buffer;
  readonly attempts: number;
  readonly max_attempts: number;
  readonly lock_token: string;
  readonly [key: string]: unknown;
}

interface DeadRow {
  readonly id: string;
  readonly topic: string;
  readonly [key: string]: unknown;
}

@Injectable()
export class OutboxStore {
  constructor(
    @Inject(DB) private readonly db: Db,
    private readonly tenantDb: TenantDb,
  ) {}

  /** Active tenants are global data; the definer function is the only reader. */
  async listActiveTenants(): Promise<readonly { id: string; code: string }[]> {
    const result = await this.db.execute<{ id: string; code: string; [key: string]: unknown }>(
      sql`SELECT id, code FROM app.list_tenants()`,
    );
    return result.rows.map((row) => ({ id: row.id, code: row.code }));
  }

  /** Duplicate `(tenant, topic, dedupeKey)` is a silent no-op. */
  async enqueue(row: OutboxInsert): Promise<boolean> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<{ id: string; [key: string]: unknown }>(sql`
        INSERT INTO integration_outbox
          (id, tenant_id, topic, dedupe_key, payload_enc, status, attempts, max_attempts,
           next_attempt_at, created_at, updated_at)
        VALUES
          (${row.id}, ${row.tenantId}, ${row.topic}, ${row.dedupeKey}, ${row.payloadEnc},
           'pending', 0, ${row.maxAttempts}, now(), now(), now())
        ON CONFLICT (tenant_id, topic, dedupe_key) DO NOTHING
        RETURNING id
      `);
      return result.rows.length > 0;
    });
  }

  /**
   * Pre-claim dead sweep (owner CP5 change 1): an expired lease whose attempts
   * already reached the max can never be claimed again, so it is moved to
   * `dead` before the claim. The claim itself also refuses `attempts >= max`,
   * so one poison row can never break the tenant's batch.
   */
  async sweepExpiredMaxAttempts(): Promise<readonly DeadOutboxRow[]> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<DeadRow>(sql`
        UPDATE integration_outbox
           SET status = 'dead',
               last_error_code = 'LEASE_EXPIRED_MAX_ATTEMPTS',
               locked_until = NULL,
               lock_token = NULL,
               updated_at = now()
         WHERE status = 'processing'
           AND locked_until < now()
           AND attempts >= max_attempts
        RETURNING id, topic
      `);
      return result.rows.map((row) => ({ id: row.id, topic: row.topic }));
    });
  }

  /** Claims due rows for the active tenant; each row gets a fresh lease token. */
  async claim(batchSize: number, leaseSeconds: number): Promise<readonly ClaimedOutboxRow[]> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<ClaimRow>(sql`
        WITH claimed AS (
          SELECT id
            FROM integration_outbox
           WHERE attempts < max_attempts
             AND (
               (status = 'pending' AND next_attempt_at <= now())
               OR (status = 'processing' AND locked_until < now())
             )
           ORDER BY next_attempt_at
           FOR UPDATE SKIP LOCKED
           LIMIT ${batchSize}
        )
        UPDATE integration_outbox o
           SET status = 'processing',
               attempts = o.attempts + 1,
               lock_token = gen_random_uuid(),
               locked_until = now() + make_interval(secs => ${leaseSeconds}),
               updated_at = now()
          FROM claimed c
         WHERE o.id = c.id
        RETURNING o.id, o.topic, o.payload_enc, o.attempts, o.max_attempts, o.lock_token
      `);
      return result.rows.map((row) => ({
        id: row.id,
        topic: row.topic,
        payloadEnc: row.payload_enc,
        attempts: row.attempts,
        maxAttempts: row.max_attempts,
        lockToken: row.lock_token,
      }));
    });
  }

  /** CAS: only the lease holder may mark a row sent. */
  async markSent(id: string, lockToken: string): Promise<boolean> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<{ id: string; [key: string]: unknown }>(sql`
        UPDATE integration_outbox
           SET status = 'sent',
               sent_at = now(),
               locked_until = NULL,
               lock_token = NULL,
               last_error_code = NULL,
               updated_at = now()
         WHERE id = ${id} AND lock_token = ${lockToken} AND status = 'processing'
        RETURNING id
      `);
      return result.rows.length > 0;
    });
  }

  /**
   * CAS failure path: back off, or move to `dead` at the attempt ceiling.
   * Returns the new status, or null when the lease was already lost.
   */
  async markFailure(
    id: string,
    lockToken: string,
    errorCode: string,
    delaySeconds: number,
  ): Promise<'pending' | 'dead' | null> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<{ status: string; [key: string]: unknown }>(sql`
        UPDATE integration_outbox
           SET status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'pending' END,
               next_attempt_at = CASE
                 WHEN attempts >= max_attempts THEN next_attempt_at
                 ELSE now() + make_interval(secs => ${delaySeconds})
               END,
               locked_until = NULL,
               lock_token = NULL,
               last_error_code = ${errorCode},
               updated_at = now()
         WHERE id = ${id} AND lock_token = ${lockToken} AND status = 'processing'
        RETURNING status
      `);
      const status = result.rows[0]?.status;
      return status === 'pending' || status === 'dead' ? status : null;
    });
  }
}
