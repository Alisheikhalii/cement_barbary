import { maskNationalId, maskPhone } from '../../security/pii/mask.js';

/**
 * Allowlisted before/after snapshots for the audit trail (ADR-009 L2).
 *
 * A snapshot is built from a per-entity FIELD ALLOWLIST, never from a raw row:
 * a column added to an entity stays invisible to the audit trail until someone
 * adds it here, so a new PII column cannot leak by default. Ciphertext/blind
 * index columns (`*_enc`, `*_hash`), password hashes, tokens and cookies are
 * not allowlistable at all.
 *
 * Plaintext personal data is additionally masked with the existing display
 * masks, so even an entity that gains a `phone`/`nationalId` field cannot store
 * the raw value through this path.
 */

const SNAPSHOTS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  user: Object.freeze([
    'id',
    'username',
    'displayName',
    'status',
    'createdAt',
    'updatedAt',
    'deletedAt',
  ]),
  user_role: Object.freeze(['userId', 'roleCode']),
});

const MAX_VALUE_LENGTH = 2_000;

/** Keys whose string value must be masked, should a future entity expose them. */
function maskValue(key: string, value: string): string {
  if (key === 'phone') {
    return maskPhone(value);
  }
  if (key === 'nationalId' || key === 'national_id') {
    return maskNationalId(value);
  }
  return value;
}

function projectValue(
  key: string,
  value: unknown,
): { readonly keep: boolean; readonly value: unknown } {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return { keep: true, value };
  }
  if (typeof value === 'string') {
    const masked = maskValue(key, value);
    return {
      keep: true,
      value: masked.length > MAX_VALUE_LENGTH ? masked.slice(0, MAX_VALUE_LENGTH) : masked,
    };
  }
  if (value instanceof Date) {
    return { keep: true, value: value.toISOString() };
  }
  // Objects and arrays are not allowlistable: a nested structure could carry a
  // field nobody reviewed.
  return { keep: false, value: undefined };
}

/**
 * Projects `row` into the audit snapshot shape for `entity`.
 * Returns `null` for an unknown entity or a non-object input (fail-closed).
 */
export function toAuditSnapshot(entity: string, row: unknown): Record<string, unknown> | null {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) {
    return null;
  }
  const allowlist = SNAPSHOTS[entity];
  if (allowlist === undefined) {
    return null;
  }
  const source = row as Record<string, unknown>;
  const snapshot: Record<string, unknown> = {};
  for (const key of allowlist) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) {
      continue;
    }
    const projected = projectValue(key, source[key]);
    if (projected.keep) {
      snapshot[key] = projected.value;
    }
  }
  return Object.keys(snapshot).length > 0 ? snapshot : null;
}

/** Re-projects a value already produced by `toAuditSnapshot` (defense in depth). */
export function projectAuditSnapshot(
  entity: string,
  value: unknown,
): Record<string, unknown> | null {
  return toAuditSnapshot(entity, value);
}
