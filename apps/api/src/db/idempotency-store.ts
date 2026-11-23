import { Injectable } from '@nestjs/common';
import { sql } from 'drizzle-orm';

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantDb as the constructor param type for DI
import { TenantDb } from './tenant-db.js';

/**
 * The only SQL path to `idempotency_keys` (ADR-010 L8/L9/L11, F1-06 T07).
 *
 * Every method goes through `TenantDb.run`, so it reuses the interceptor's open
 * transaction: the claim, the handler's writes and the completed row commit or
 * roll back together. RLS pins the tenant from the request context; the scope
 * columns are still passed explicitly to hit the unique index.
 */

export interface IdempotencyScope {
  readonly tenantId: string;
  readonly userId: string;
  readonly routeKey: string;
  readonly idemKey: string;
}

export interface IdempotencyRow {
  readonly id: string;
  readonly tenantId: string;
  readonly status: string;
  readonly fingerprint: Buffer;
  readonly responseStatus: number | null;
  readonly responseEnc: Buffer | null;
  /** Computed by the DB clock, not the app clock. */
  readonly expired: boolean;
}

interface ClaimRow {
  readonly id: string;
  readonly [key: string]: unknown;
}

interface SelectRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly status: string;
  readonly fingerprint: Buffer;
  readonly response_status: number | null;
  readonly response_enc: Buffer | null;
  readonly expired: boolean;
  readonly [key: string]: unknown;
}

@Injectable()
export class IdempotencyStore {
  constructor(private readonly tenantDb: TenantDb) {}

  /**
   * Transaction-local timeouts (owner CP4 change 1): the lock wait on the
   * unique key and the statement timeout aligned with the handler cap, so the
   * database side stops even when the JS handler cannot be cancelled.
   */
  async applyTimeouts(lockTimeoutMs: number, statementTimeoutMs: number): Promise<void> {
    await this.tenantDb.run(async (tx) => {
      await tx.execute(sql`select set_config('lock_timeout', ${`${lockTimeoutMs}ms`}, true)`);
      await tx.execute(
        sql`select set_config('statement_timeout', ${`${statementTimeoutMs}ms`}, true)`,
      );
    });
  }

  /** Claim or return null when another transaction already owns the key. */
  async claim(
    scope: IdempotencyScope,
    id: string,
    fingerprint: Buffer,
    ttlHours: number,
  ): Promise<string | null> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<ClaimRow>(sql`
        INSERT INTO idempotency_keys
          (id, tenant_id, user_id, route_key, idem_key, fingerprint, status, created_at, expires_at)
        VALUES
          (${id}, ${scope.tenantId}, ${scope.userId}, ${scope.routeKey}, ${scope.idemKey},
           ${fingerprint}, 'in_progress', now(), now() + make_interval(hours => ${ttlHours}))
        ON CONFLICT (tenant_id, user_id, route_key, idem_key) DO NOTHING
        RETURNING id
      `);
      return result.rows[0]?.id ?? null;
    });
  }

  /** Reads the conflicting row (the claim already waited for it to commit). */
  async find(scope: IdempotencyScope): Promise<IdempotencyRow | null> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<SelectRow>(sql`
        SELECT id, tenant_id, status, fingerprint, response_status, response_enc,
               (expires_at < now()) AS expired
          FROM idempotency_keys
         WHERE tenant_id = ${scope.tenantId}
           AND user_id = ${scope.userId}
           AND route_key = ${scope.routeKey}
           AND idem_key = ${scope.idemKey}
         LIMIT 1
      `);
      const row = result.rows[0];
      if (row === undefined) {
        return null;
      }
      return {
        id: row.id,
        tenantId: row.tenant_id,
        status: row.status,
        fingerprint: row.fingerprint,
        responseStatus: row.response_status,
        responseEnc: row.response_enc,
        expired: row.expired,
      };
    });
  }

  /**
   * CAS takeover of an expired row: only one concurrent request can move
   * `expires_at` from the past to the future, so exactly one handler executes.
   */
  async takeOver(
    scope: IdempotencyScope,
    id: string,
    fingerprint: Buffer,
    ttlHours: number,
  ): Promise<boolean> {
    return this.tenantDb.run(async (tx) => {
      const result = await tx.execute<ClaimRow>(sql`
        UPDATE idempotency_keys
           SET status = 'in_progress',
               fingerprint = ${fingerprint},
               response_status = NULL,
               response_enc = NULL,
               created_at = now(),
               expires_at = now() + make_interval(hours => ${ttlHours})
         WHERE id = ${id}
           AND tenant_id = ${scope.tenantId}
           AND user_id = ${scope.userId}
           AND expires_at < now()
        RETURNING id
      `);
      return result.rows.length > 0;
    });
  }

  /** Stores the successful response; only a claimed row may complete. */
  async complete(
    scope: IdempotencyScope,
    id: string,
    responseStatus: number,
    responseEnc: Buffer,
  ): Promise<void> {
    await this.tenantDb.run(async (tx) => {
      const result = await tx.execute<ClaimRow>(sql`
        UPDATE idempotency_keys
           SET status = 'completed', response_status = ${responseStatus}, response_enc = ${responseEnc}
         WHERE id = ${id}
           AND tenant_id = ${scope.tenantId}
           AND user_id = ${scope.userId}
           AND status = 'in_progress'
        RETURNING id
      `);
      if (result.rows.length === 0) {
        throw new Error('IDEMPOTENCY_CLAIM_LOST');
      }
    });
  }
}
