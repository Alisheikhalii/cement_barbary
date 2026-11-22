import { Injectable } from '@nestjs/common';

import { auditLogs } from './schema/audit-logs.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantDb as the constructor param type for DI
import { TenantDb } from './tenant-db.js';

/** One row to append; `occurred_at` is never supplied (the DB trigger owns it). */
export type AuditInsert = Omit<typeof auditLogs.$inferInsert, 'occurredAt'>;

/**
 * The only write path to `audit_logs` (ADR-009 L1, F1-06 T05).
 *
 * It goes through `TenantDb.run`, so it either reuses the caller's open
 * transaction (success rows: the audit row commits or rolls back with the
 * business change) or opens its own short transaction (failure/denial rows,
 * best-effort). The RLS policy pins the tenant from the request context.
 */
@Injectable()
export class AuditStore {
  constructor(private readonly tenantDb: TenantDb) {}

  async append(row: AuditInsert): Promise<void> {
    await this.tenantDb.run(async (tx) => {
      await tx.insert(auditLogs).values(row);
    });
  }
}
