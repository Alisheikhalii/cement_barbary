import { Injectable } from '@nestjs/common';

/**
 * Sensitive-action audit contract (ADR-008 Z10, F1-05 T06).
 *
 * The interceptor calls `record()` AFTER the handler settles, once for every
 * sensitive route, with `success` or `failure`. The reason is the validated
 * `reason` body field (trimmed), or `null` when validation itself failed.
 * The no-op implementation below is replaced by the real F1-06 audit module;
 * nothing else in F1-05 persists or logs the reason.
 */

export type AuditOutcome = 'success' | 'failure';

export interface AuditActor {
  readonly userId: string;
  readonly tenantId: string;
  readonly sessionId: string;
}

export interface AuditResource {
  /** Stable resource kind, e.g. `handler`. Never a user-supplied value. */
  readonly type: string;
  /** Stable resource id, e.g. `Controller.method` or a later domain id. */
  readonly id: string;
}

export interface AuditRecord {
  readonly actor: AuditActor;
  /** The sensitive permission name — code, not user input. */
  readonly action: string;
  readonly resource: AuditResource;
  /** Validated, trimmed reason; null when the body never validated. */
  readonly reason: string | null;
  readonly outcome: AuditOutcome;
}

export interface AuditHook {
  record(entry: AuditRecord): void | Promise<void>;
}

/** Nest DI token; F1-06 replaces this provider with the persistent hook. */
export const AUDIT_HOOK = Symbol('AUDIT_HOOK');

@Injectable()
export class NoopAuditHook implements AuditHook {
  record(_entry: AuditRecord): void {
    // F1-06 owns persistence. This implementation deliberately does nothing.
    void _entry;
  }
}
