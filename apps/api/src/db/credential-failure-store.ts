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
   * Records one failure. A random tenant/user (the dummy path) matches zero
   * rows and still pays the same transaction shape.
   */
  async record(
    tenantId: string,
    userId: string,
    failedAttempts: number,
    nextAttemptAt: Date,
  ): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`select set_config('app.tenant_id', ${tenantId}, true)`);
      await tx.execute(sql`select set_config('app.carrier_id', '', true)`);
      await tx.execute(sql`set local synchronous_commit = off`);
      await tx.execute(sql`
        UPDATE user_credentials
        SET failed_attempts = ${failedAttempts},
            next_attempt_at = ${nextAttemptAt},
            updated_at = now()
        WHERE tenant_id = ${tenantId} AND user_id = ${userId}
      `);
    });
  }
}
