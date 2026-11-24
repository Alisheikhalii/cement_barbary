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
    // Role codes only (never a user-supplied string); see projectValue.
    'roles',
    'createdAt',
    'updatedAt',
    'deletedAt',
  ]),
  user_role: Object.freeze(['userId', 'roleCode']),
  // F1-07 base data (ADR-011 B8): business fields + version + deletedAt.
  // `nameKey` and `tenantId` are intentionally absent.
  destination: Object.freeze([
    'id',
    'name',
    'provinceName',
    'isActive',
    'displayOrder',
    'version',
    'createdAt',
    'updatedAt',
    'deletedAt',
  ]),
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
    // C0 controls are stripped so the writer's jsonb-size estimate matches the
    // server (jsonb escapes control characters more verbosely than
    // JSON.stringify) and so an audit row never contains terminal control
    // bytes from a future caller.
    // eslint-disable-next-line no-control-regex -- deliberate: strip C0/DEL bytes
    const masked = maskValue(key, value).replace(/[\u0000-\u001F\u007F]/g, '');
    return {
      keep: true,
      value: masked.length > MAX_VALUE_LENGTH ? masked.slice(0, MAX_VALUE_LENGTH) : masked,
    };
  }
  if (value instanceof Date) {
    return { keep: true, value: value.toISOString() };
  }
  // The single array exception: a role-code set on `user`. Codes come from the
  // closed catalog, are sorted (deterministic snapshots) and bounded.
  // Role-code shape only: the closed-catalog check happens on the write path
  // (roleCodeSchema in UserRoleService) and in the `user_roles` FK. The role
  // constants are owned by the users module and importing them here is
  // lint-restricted (ADR-008 Z5), so this layer stays shape-strict and bounded.
  if (key === 'roles' && Array.isArray(value)) {
    const codes = value.filter(
      (item): item is string => typeof item === 'string' && /^[A-Z][A-Z0-9_]{0,31}$/.test(item),
    );
    if (codes.length === value.length && codes.length <= 16) {
      return { keep: true, value: [...new Set(codes)].sort() };
    }
    return { keep: false, value: undefined };
  }
  // Other objects and arrays are not allowlistable: a nested structure could
  // carry a field nobody reviewed.
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
