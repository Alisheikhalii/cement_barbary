/**
 * Sensitive-action audit contract (ADR-008 Z10, F1-05 T06, F1-06 T05).
 *
 * The interceptor calls `record()` once for every sensitive route: `success`
 * inside the handler's transaction (fail-closed), `failure` after its rollback
 * (best-effort), and the guard calls it with `denied` for a sensitive 403. The
 * reason is the validated `reason` body field (trimmed), or `null` when
 * validation itself failed. The persistent implementation lives in
 * `src/modules/audit/`; nothing here persists or logs by itself.
 */

export type AuditOutcome = 'success' | 'failure' | 'denied';

/**
 * A before/after change collected through `auditChange()` (F1-06 T05). The
 * structural shape is repeated here instead of importing the audit module, so
 * the authz layer keeps no runtime dependency on it (type-only consumers).
 */
export interface AuditChangeRecord {
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly before: unknown;
  readonly after: unknown;
}

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
  /** Final HTTP status (F1-06 T05 closes the F1-05 outcome-vs-status note). */
  readonly httpStatus?: number | null;
  readonly requestId?: string | null;
  /** Raw client IP; the persistent hook encrypts it before storage. */
  readonly ip?: string | null;
  /** Carrier scope of the principal (F1-08); keeps the hook in the same ALS scope. */
  readonly carrierId?: string | null;
  /** Snapshots collected during the handler by `auditChange()` (T05). */
  readonly changes?: readonly AuditChangeRecord[];
}

export interface AuditHook {
  record(entry: AuditRecord): void | Promise<void>;
}

/** Nest DI token; bound to `PersistentAuditHook` by AuditModule (F1-06 T05). */
export const AUDIT_HOOK = Symbol('AUDIT_HOOK');
