import { describe, expect, it, inject } from 'vitest';

import { runMigrations } from '../src/db/migrate.js';
import { ownerPool } from './setup/db.js';

/**
 * Proves the migration chain and the runtime-role security posture on a real
 * PostgreSQL 17 (the container from the global setup already ran all
 * migrations on an empty database — setup succeeding is itself proof of (1)).
 */
describe('migrations (integration)', () => {
  it('applied all migrations on an empty DB and a re-run is a no-op', async () => {
    const owner = ownerPool();
    // The journal table stores (id, hash, created_at) — one row per applied migration.
    const journal = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations',
    );
    expect(journal.rows[0]?.n).toBe(2);

    // Second run: no error, no new journal rows.
    await expect(runMigrations(inject('ownerUrl'))).resolves.toBeUndefined();
    const again = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations',
    );
    expect(again.rows[0]?.n).toBe(2);
  });

  it('bitabar_app has no superuser, bypass-rls, create-role or login-via-git privileges', async () => {
    const result = await ownerPool().query<{
      rolsuper: boolean;
      rolbypassrls: boolean;
      rolcreaterole: boolean;
      rolcreatedb: boolean;
    }>(
      `SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb
       FROM pg_roles WHERE rolname = 'bitabar_app'`,
    );
    expect(result.rows).toEqual([
      { rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false },
    ]);
  });

  it('bitabar_app does not own the tenants table', async () => {
    const result = await ownerPool().query<{ tableowner: string }>(
      `SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'tenants'`,
    );
    expect(result.rows[0]?.tableowner).not.toBe('bitabar_app');
  });

  it('tenants has row-level security enabled', async () => {
    const result = await ownerPool().query<{ relrowsecurity: boolean }>(
      `SELECT relrowsecurity FROM pg_class
       WHERE relname = 'tenants' AND relnamespace = 'public'::regnamespace`,
    );
    expect(result.rows[0]?.relrowsecurity).toBe(true);
  });
});
