import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Before/after capture for the audit trail (ADR-009 L2, F1-06 T05).
 *
 * A domain service calls `auditChange()` while a unit of work is running; the
 * audit writer consumes what it collected and stores it with the same
 * transaction as the business change. There is deliberately no way to append a
 * change outside `runWithAuditChanges()`: an unaudited change would be silent,
 * so `auditChange()` throws instead (fail-closed).
 *
 * The scope is intentionally per-request/per-unit-of-work, not Nest
 * request-scoped: the interceptor opens it around the handler, and a CLI or
 * worker command opens its own.
 */

export interface AuditChange {
  /** Stable entity kind, e.g. `user`. Must match the snapshot allowlist key. */
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly before: unknown;
  readonly after: unknown;
}

interface AuditScope {
  readonly changes: AuditChange[];
}

const storage = new AsyncLocalStorage<AuditScope>();

const RESOURCE_TYPE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_RESOURCE_ID_LENGTH = 128;
const MAX_CHANGES_PER_ENTRY = 10;

/** Collects every `auditChange()` call made inside `fn`. */
export async function runWithAuditChanges<T>(
  fn: () => Promise<T>,
): Promise<{ readonly result: T; readonly changes: readonly AuditChange[] }> {
  const scope: AuditScope = { changes: [] };
  return storage.run(scope, async () => {
    const result = await fn();
    return { result, changes: scope.changes };
  });
}

/**
 * Records what a domain service changed. Snapshots must already be projection
 * results (`toAuditSnapshot`); the writer re-projects as defense in depth.
 */
export function auditChange(change: AuditChange): void {
  const scope = storage.getStore();
  if (scope === undefined) {
    throw new Error('AUDIT_CONTEXT_MISSING');
  }
  if (!RESOURCE_TYPE_PATTERN.test(change.resourceType)) {
    throw new Error('AUDIT_CHANGE_INVALID');
  }
  if (
    change.resourceId !== null &&
    (typeof change.resourceId !== 'string' ||
      change.resourceId.length === 0 ||
      change.resourceId.length > MAX_RESOURCE_ID_LENGTH)
  ) {
    throw new Error('AUDIT_CHANGE_INVALID');
  }
  if (scope.changes.length >= MAX_CHANGES_PER_ENTRY) {
    // A runaway loop must not produce an unbounded jsonb payload; the DB cap
    // would reject it anyway, and failing here keeps the error local.
    throw new Error('AUDIT_CHANGE_LIMIT');
  }
  scope.changes.push(Object.freeze({ ...change }));
}

/** The changes collected so far in the active scope (empty outside one). */
export function currentAuditChanges(): readonly AuditChange[] {
  return storage.getStore()?.changes ?? [];
}
