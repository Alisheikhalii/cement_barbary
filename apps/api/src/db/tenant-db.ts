import { Inject, Injectable } from '@nestjs/common';
import { sql } from 'drizzle-orm';

import { DomainError } from '../common/errors/domain-error.js';
import { DB, type Db } from './database.providers.js';
import { getTenantStore, runWithTenantTx } from './tenant-context.js';

/** Transaction handle handed to TenantDb.run callbacks (extracted from Db). */
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];

export interface TenantRunOptions {
  readonly isolationLevel?: 'read committed' | 'repeatable read' | 'serializable';
}

/**
 * The single, enforced path to tenant data (ADR-005 D5/D6/D10). Every tenant
 * query runs inside a transaction whose RLS context is pinned to the current
 * TenantContext scope with transaction-local, parameterized set_config calls —
 * pooled connections never keep a tenant. Missing context fails closed with
 * TENANT_CONTEXT_MISSING: never a default tenant, never a non-transactional
 * query.
 */
@Injectable()
export class TenantDb {
  constructor(@Inject(DB) private readonly db: Db) {}

  /**
   * Runs `fn` in a tenant-scoped transaction.
   *
   * A nested call while a transaction is already active for the SAME scope
   * reuses that transaction — no new connection, no new BEGIN — and its
   * `isolationLevel` is IGNORED (the outer transaction's level wins). A scope
   * switch while a transaction is active is rejected earlier, by
   * TenantContext.run.
   */
  async run<T>(fn: (tx: Tx) => Promise<T>, opts?: TenantRunOptions): Promise<T> {
    const store = getTenantStore();
    if (!store) {
      throw DomainError.tenantContextMissing();
    }
    if (store.tx !== undefined) {
      // Nested run with the same scope: reuse the active transaction.
      return fn(store.tx as Tx);
    }
    const { scope } = store;
    const config =
      opts?.isolationLevel === undefined ? undefined : { isolationLevel: opts.isolationLevel };
    return this.db.transaction(async (tx) => {
      // Transaction-local (is_local = true) and parameterized. carrier_id is
      // always set — '' when the scope has none — so nothing is inherited
      // (app.current_carrier_id() maps '' to NULL via NULLIF).
      await tx.execute(sql`select set_config('app.tenant_id', ${scope.tenantId}, true)`);
      await tx.execute(sql`select set_config('app.carrier_id', ${scope.carrierId ?? ''}, true)`);
      return runWithTenantTx(tx, () => fn(tx));
    }, config);
  }
}
