import { randomBytes } from 'node:crypto';

import { Pool, type PoolConfig } from 'pg';
import { inject } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { buildAad, PiiService } from '../../src/security/pii/pii-crypto.js';
import { normalizePhone } from '../../src/security/pii/normalize.js';

/**
 * Helpers for integration tests. `ownerPool`/`appPool` are shared per test
 * process (closed by Vitest on exit); `makeAppPool` returns a caller-managed
 * pool for tests that need a specific configuration (e.g. max: 1).
 */

let sharedOwner: Pool | undefined;
let sharedApp: Pool | undefined;

/** Schema-owner pool (bypasses RLS — use only for setup and assertions about the schema). */
export function ownerPool(): Pool {
  sharedOwner ??= new Pool({ connectionString: inject('ownerUrl') });
  return sharedOwner;
}

/** Runtime-role pool (bitabar_app — RLS applies). */
export function appPool(): Pool {
  sharedApp ??= new Pool({ connectionString: inject('appUrl') });
  return sharedApp;
}

/** Fresh runtime-role pool with caller-chosen config; the caller must end() it. */
export function makeAppPool(config: PoolConfig = {}): Pool {
  return new Pool({ connectionString: inject('appUrl'), ...config });
}

/** Inserts a tenant row as the owner (D13) and returns its id. Codes must be unique per test. */
export async function createTenant(pool: Pool, code: string): Promise<string> {
  const id = uuidv7();
  await pool.query('INSERT INTO tenants (id, code, name) VALUES ($1, $2, $3)', [id, code, code]);
  return id;
}

let pii: PiiService | undefined;

/**
 * PII service for fixtures, keyed from the test env (the int global setup
 * provides random per-run keys; the ??= fallback keeps the helper usable
 * without it). Fixture blobs never leave the throwaway container.
 */
export function testPii(): PiiService {
  if (!pii) {
    const encKey = Buffer.from(
      (process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64')),
      'base64',
    );
    const hmacKey = Buffer.from(
      (process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64')),
      'base64',
    );
    pii = new PiiService({ encKey, hmacKey, keyId: 1 });
  }
  return pii;
}

export interface CreateUserOptions {
  username?: string;
  displayName?: string;
  /** Synthetic number from the gitleaks allowlist; stored encrypted + hashed (U7/U8). */
  phone?: string;
}

/**
 * Inserts a user as the owner (setup only — RLS would hide the write context).
 * The id is generated app-side BEFORE encrypting (U7), exactly like the
 * production write path. National-ID columns are never touched (owner Q3).
 */
export async function createUser(
  pool: Pool,
  tenantId: string,
  opts: CreateUserOptions = {},
): Promise<string> {
  const id = uuidv7();
  let phoneEnc: Buffer | null = null;
  let phoneHash: Buffer | null = null;
  if (opts.phone) {
    const normalized = normalizePhone(opts.phone);
    phoneHash = testPii().blindIndex('phone', tenantId, normalized);
    phoneEnc = testPii().encrypt(normalized, buildAad(tenantId, 'users.phone_enc', id));
  }
  await pool.query(
    `INSERT INTO users (id, tenant_id, username, display_name, phone_enc, phone_hash)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [id, tenantId, opts.username ?? null, opts.displayName ?? 'Test User', phoneEnc, phoneHash],
  );
  return id;
}

/**
 * Inserts a user with caller-chosen phone_hash bytes (constraint-level
 * fixture: identical hashes across tenants). phone_enc carries placeholder
 * bytes — the pair CHECK only requires both set; this is not real ciphertext.
 */
export async function createUserWithPhoneHash(
  pool: Pool,
  tenantId: string,
  phoneHash: Buffer,
): Promise<string> {
  const id = uuidv7();
  await pool.query(
    `INSERT INTO users (id, tenant_id, display_name, phone_enc, phone_hash)
     VALUES ($1, $2, 'Hash Fixture', $3, $4)`,
    [id, tenantId, Buffer.from([1, 2, 3]), phoneHash],
  );
  return id;
}

/** Links a role to a user as the owner (fixture setup). */
export async function assignRole(
  pool: Pool,
  tenantId: string,
  userId: string,
  roleCode: string,
  roleScope: string,
): Promise<void> {
  await pool.query(
    'INSERT INTO user_roles (tenant_id, user_id, role_code, role_scope) VALUES ($1, $2, $3, $4)',
    [tenantId, userId, roleCode, roleScope],
  );
}
