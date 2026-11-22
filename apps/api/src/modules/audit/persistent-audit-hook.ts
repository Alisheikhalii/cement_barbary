import { Injectable } from '@nestjs/common';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';

import { sanitizeErrorForLog } from '../../common/logging/sanitize-error.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantContext as the constructor param type for DI
import { TenantContext } from '../../db/tenant-context.js';
import type { AuditHook, AuditRecord } from '../../security/authz/audit-hook.js';
import type { AuditAppendEntry } from './audit-writer.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits AuditWriter as the constructor param type for DI
import { AuditWriter } from './audit-writer.js';

/**
 * The persistent AuditHook (ADR-009 L1b/L6, F1-06 T05).
 *
 * - The success record is written while the interceptor's transaction is still
 *   open, so it commits atomically with the sensitive change. A success write
 *   failure PROPAGATES (the transaction rolls back, fail-closed) — this is the
 *   one case where the hook is allowed to reject.
 * - `failure` and `denied` records are best-effort: they open their own short
 *   transaction after the original transaction rolled back (C3), are bounded by
 *   a timeout, and a write failure NEVER changes the HTTP response.
 * - A failed best-effort write is never silent (owner CP1): a sanitized
 *   security-log event with an error code and structural fields only — no
 *   reason text, no payload, no IP. There is no metrics hook in F1-06; when one
 *   is added, this is the counter to increment (`audit.write_failed`).
 */

/** Best-effort writes may not hold a request open while the DB is unhealthy. */
const BEST_EFFORT_TIMEOUT_MS = 2_000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('AUDIT_WRITE_TIMEOUT')), ms);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error('AUDIT_WRITE_FAILED'));
      },
    );
  });
}

@Injectable()
export class PersistentAuditHook implements AuditHook {
  constructor(
    private readonly tenantContext: TenantContext,
    private readonly writer: AuditWriter,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(PersistentAuditHook.name);
  }

  async record(record: AuditRecord): Promise<void> {
    const append = (): Promise<string> => this.writer.append(this.toEntry(record));
    if (record.outcome === 'success') {
      // Fail-closed (ADR-009 L1): this runs inside the caller's transaction, so
      // a failed write must propagate and roll the business change back. It is
      // never timed out and never swallowed.
      await this.runAppend(record, append);
      return;
    }
    try {
      // Best-effort (C3): own short transaction, bounded, never changes the
      // response; a failure is logged with structural fields only.
      await withTimeout(this.runAppend(record, append), BEST_EFFORT_TIMEOUT_MS);
    } catch (error) {
      this.reportFailure(record, error);
    }
  }

  /**
   * Reuses the active scope when it is the same tenant+carrier (the interceptor
   * already opened it, and `TenantContext.run` would reject a different scope
   * while its transaction is open). A denial from the guard has no active
   * scope, so it opens its own.
   */
  private runAppend(record: AuditRecord, append: () => Promise<string>): Promise<string> {
    const active = this.tenantContext.current();
    const carrierId = record.carrierId ?? undefined;
    if (active?.tenantId === record.actor.tenantId && active.carrierId === carrierId) {
      return append();
    }
    const scope =
      carrierId === undefined
        ? { tenantId: record.actor.tenantId }
        : { tenantId: record.actor.tenantId, carrierId };
    return this.tenantContext.run(scope, append);
  }

  /** Structural fields only: request id, outcome, a stable code, sanitized error. */
  private reportFailure(record: AuditRecord, error: unknown): void {
    this.logger.warn(
      {
        reqId: record.requestId ?? null,
        outcome: record.outcome,
        code: 'AUDIT_WRITE_FAILED',
        err: sanitizeErrorForLog(error),
      },
      'audit write failed',
    );
  }

  private toEntry(record: AuditRecord): AuditAppendEntry {
    const changes = record.changes ?? [];
    const last = changes.length > 0 ? changes[changes.length - 1] : undefined;
    return {
      actorType: 'user',
      actorUserId: record.actor.userId,
      actorSessionId: record.actor.sessionId,
      action: record.action,
      // When a domain change was captured, the row describes THAT resource
      // (what changed); otherwise it describes the audited handler. The
      // snapshot allowlist is keyed by this entity, so it must be the change's
      // entity or the before/after projection drops everything.
      resourceType: last?.resourceType ?? record.resource.type,
      resourceId: last?.resourceId ?? record.resource.id,
      outcome: record.outcome,
      httpStatus: record.httpStatus ?? null,
      reason: record.reason,
      ...(last === undefined ? {} : { before: last.before, after: last.after }),
      ...(last === undefined
        ? {}
        : {
            metadata: {
              handler: record.resource.id,
              ...(changes.length > 1
                ? {
                    changeCount: changes.length,
                    resources: changes.map((change) => change.resourceType),
                  }
                : {}),
            },
          }),
      ip: record.ip ?? null,
      requestId: record.requestId ?? null,
    };
  }
}
