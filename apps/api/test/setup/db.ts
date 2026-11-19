import { Pool, type PoolConfig } from 'pg';
import { inject } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

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
