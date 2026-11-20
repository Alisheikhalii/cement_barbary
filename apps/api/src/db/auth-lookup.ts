import { sql } from 'drizzle-orm';

import type { Db } from './database.providers.js';

/**
 * Typed access to the pre-auth SECURITY DEFINER lookups (ADR-007 A17, T04).
 * These are the ONLY reads that run without a tenant context; they never
 * return PII or ciphertext beyond `password_hash` (the lookup's purpose).
 * Lives inside src/db/** because raw SQL is confined to this boundary (D11).
 */

/** Cap on fan-out pairs — keep in sync with the guard in 0007_auth_lookup_functions.sql. */
export const AUTH_LOOKUP_MAX_PAIRS = 500;

/** One matched account, camelCase. Field-by-field — never a row spread. */
export interface AuthLookupRow {
  readonly tenantId: string;
  readonly userId: string;
  readonly passwordHash: string;
  readonly status: string;
  readonly mustChangePassword: boolean;
  readonly failedAttempts: number;
  readonly nextAttemptAt: Date | null;
  readonly temporaryPasswordExpiresAt: Date | null;
  readonly roles: readonly string[];
}

/**
 * Drizzle's node-postgres raw `execute` keeps timestamps as strings (its
 * typed query builder maps them to Date, but raw results do not) — normalize
 * here so the public types are honest.
 */
function toDateOrNull(value: Date | string | null): Date | null {
  if (value === null) return null;
  return value instanceof Date ? value : new Date(value);
}

interface RawRow extends Record<string, unknown> {
  tenant_id: string;
  user_id: string;
  password_hash: string;
  status: string;
  must_change_password: boolean;
  failed_attempts: number;
  next_attempt_at: Date | string | null;
  temporary_password_expires_at: Date | string | null;
  roles: string[];
}

function toRow(raw: RawRow): AuthLookupRow {
  return {
    tenantId: raw.tenant_id,
    userId: raw.user_id,
    passwordHash: raw.password_hash,
    status: raw.status,
    mustChangePassword: raw.must_change_password,
    failedAttempts: raw.failed_attempts,
    nextAttemptAt: toDateOrNull(raw.next_attempt_at),
    temporaryPasswordExpiresAt: toDateOrNull(raw.temporary_password_expires_at),
    roles: raw.roles ?? [],
  };
}

export async function listTenants(db: Db): Promise<{ id: string; code: string }[]> {
  const result = await db.execute<{ id: string; code: string }>(
    sql`SELECT id, code FROM app.list_tenants()`,
  );
  return result.rows.map((row) => ({ id: row.id, code: row.code }));
}

/** Session resolution for refresh/logout (owner-condition-4 note in 0007). */
export interface AuthSessionLookupRow {
  readonly sessionId: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly familyId: string;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
  readonly rotatedAt: Date | null;
  /** True when the presented hash is the ROTATED-OUT one — reuse (A8). */
  readonly reuseDetected: boolean;
}

interface RawSessionRow extends Record<string, unknown> {
  session_id: string;
  tenant_id: string;
  user_id: string;
  family_id: string;
  expires_at: Date | string;
  revoked_at: Date | string | null;
  rotated_at: Date | string | null;
  reuse_detected: boolean;
}

/**
 * Resolve a refresh token (by its SHA-256 hash, hex) to its session without a
 * tenant context. Returns null for unknown/malformed input — the caller turns
 * that into the generic 401. `reuseDetected` must revoke the whole family.
 */
export async function authLookupSession(
  db: Db,
  refreshHash: Buffer,
): Promise<AuthSessionLookupRow | null> {
  const result = await db.execute<RawSessionRow>(
    sql`SELECT * FROM app.auth_lookup_session(${refreshHash.toString('hex')})`,
  );
  const raw = result.rows[0];
  if (!raw) {
    return null;
  }
  return {
    sessionId: raw.session_id,
    tenantId: raw.tenant_id,
    userId: raw.user_id,
    familyId: raw.family_id,
    expiresAt: toDateOrNull(raw.expires_at) as Date,
    revokedAt: toDateOrNull(raw.revoked_at),
    rotatedAt: toDateOrNull(raw.rotated_at),
    reuseDetected: raw.reuse_detected,
  };
}

/** Staff lookup by `username@tenant-code` — at most one row. */
export async function authLookupUsername(
  db: Db,
  tenantCode: string,
  username: string,
): Promise<AuthLookupRow[]> {
  const result = await db.execute<RawRow>(
    sql`SELECT * FROM app.auth_lookup_username(${tenantCode}, ${username})`,
  );
  return result.rows.map(toRow);
}

/**
 * Driver fan-out over (tenant_id, blind-index hash) pairs. Raw phone numbers
 * never enter this function (A4). Empty or over-cap input short-circuits to
 * the same empty result the functions return for unknown input.
 */
export async function authLookupPhone(
  db: Db,
  pairs: readonly { tenantId: string; phoneHash: Buffer }[],
): Promise<AuthLookupRow[]> {
  if (pairs.length === 0 || pairs.length > AUTH_LOOKUP_MAX_PAIRS) {
    return [];
  }
  const payload = JSON.stringify(
    pairs.map((pair) => ({ tenant_id: pair.tenantId, phone_hash: pair.phoneHash.toString('hex') })),
  );
  const result = await db.execute<RawRow>(
    sql`SELECT * FROM app.auth_lookup_phone(${payload}::jsonb)`,
  );
  return result.rows.map(toRow);
}
