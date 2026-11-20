import { Inject, Injectable } from '@nestjs/common';
import { sql } from 'drizzle-orm';

import { DB, type Db } from './database.providers.js';

/**
 * Progressive-delay bookkeeping (ADR-007 A2) with a timing-equal cost for
 * paths that must NOT write a counter (unknown identifiers, delayed accounts).
 *
 * Two properties matter here:
 *  - the tenant context is transaction-local, exactly like TenantDb (RLS
 *    applies to the UPDATE);
 *  - `SET LOCAL synchronous_commit = off` skips the WAL flush wait. A delay
 *    counter is best-effort anti-brute-force state, not data that must survive
 *    a crash, and skipping the fsync keeps the real wrong-password path as
 *    cheap as the no-op dummy write the unknown paths perform (A3 timing).
 *    Every other write in the system keeps full durability.
 */
@Injectable()
export class CredentialFailureStore {
  constructor(@Inject(DB) private readonly db: Db) {}

  /**
   * Records one failure atomically: `failed_attempts = failed_attempts + 1`
   * and the delay `base × 2^(n-1)` (capped) are computed in the same UPDATE,
   * so parallel wrong guesses can never overwrite each other with a stale
   * count (phase review L2). A random tenant/user (the dummy path) matches
   * zero rows and still pays the same transaction shape.
   */
  async record(
    tenantId: string,
    userId: string,
    baseSeconds: number,
    maxSeconds: number,
  ): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`select set_config('app.tenant_id', ${tenantId}, true)`);
      await tx.execute(sql`select set_config('app.carrier_id', '', true)`);
      await tx.execute(sql`set local synchronous_commit = off`);
      await tx.execute(sql`
        UPDATE user_credentials
        SET failed_attempts = failed_attempts + 1,
            next_attempt_at = now() + (
              LEAST(
                ${maxSeconds}::double precision,
                ${baseSeconds}::double precision * power(2, LEAST(failed_attempts, 30))
              ) * interval '1 second'
            ),
            updated_at = now()
        WHERE tenant_id = ${tenantId} AND user_id = ${userId}
      `);
    });
  }
}
