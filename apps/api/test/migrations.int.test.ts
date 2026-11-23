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
    expect(journal.rows[0]?.n).toBe(15);

    // Second run: no error, no new journal rows.
    await expect(runMigrations(inject('ownerUrl'))).resolves.toBeUndefined();
    const again = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations',
    );
    expect(again.rows[0]?.n).toBe(15);
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

  it('tenant-owned tables have row-level security enabled (auth and audit tables included)', async () => {
    const result = await ownerPool().query<{ relname: string; relrowsecurity: boolean }>(
      `SELECT relname, relrowsecurity FROM pg_class
       WHERE relname = ANY ('{tenants,users,user_roles,auth_sessions,user_credentials,audit_logs,idempotency_keys}')
         AND relnamespace = 'public'::regnamespace
       ORDER BY relname`,
    );
    expect(result.rows).toEqual([
      { relname: 'audit_logs', relrowsecurity: true },
      { relname: 'auth_sessions', relrowsecurity: true },
      { relname: 'idempotency_keys', relrowsecurity: true },
      { relname: 'tenants', relrowsecurity: true },
      { relname: 'user_credentials', relrowsecurity: true },
      { relname: 'user_roles', relrowsecurity: true },
      { relname: 'users', relrowsecurity: true },
    ]);
  });

  it('roles holds exactly the 3 catalog rows (ADR-006 U1, trimmed by 0004 in T05b)', async () => {
    const result = await ownerPool().query<{ code: string; scope: string }>(
      'SELECT code, scope FROM roles ORDER BY code',
    );
    expect(result.rows).toEqual([
      { code: 'CARRIER_ADMIN', scope: 'carrier' },
      { code: 'DRIVER', scope: 'driver' },
      { code: 'FACTORY_OPERATOR', scope: 'tenant' },
    ]);
  });

  it('stores the Persian role names byte-exactly in logical order', async () => {
    // Expected names built from Unicode CODE POINTS (no RTL literals in this
    // file, so no editor/terminal bidi rendering can distort them); compared
    // at the BYTE level (UTF-8 hex), not as text.
    const fa = (...codes: number[]) => String.fromCodePoint(...codes);
    const expected: Record<string, string> = {
      // اپراتور کارخانه
      FACTORY_OPERATOR: fa(
        0x627,
        0x67e,
        0x631,
        0x627,
        0x62a,
        0x648,
        0x631,
        0x20,
        0x6a9,
        0x627,
        0x631,
        0x62e,
        0x627,
        0x646,
        0x647,
      ),
      // مدیر باربری
      CARRIER_ADMIN: fa(0x645, 0x62f, 0x6cc, 0x631, 0x20, 0x628, 0x627, 0x631, 0x628, 0x631, 0x6cc),
      // راننده
      DRIVER: fa(0x631, 0x627, 0x646, 0x646, 0x62f, 0x647),
    };
    const result = await ownerPool().query<{ code: string; name_fa: string; hex: string }>(
      `SELECT code, name_fa, encode(convert_to(name_fa, 'UTF8'), 'hex') AS hex
       FROM roles ORDER BY code`,
    );
    expect(result.rows).toHaveLength(3);
    for (const row of result.rows) {
      const want = expected[row.code];
      expect(want, `unexpected role ${row.code}`).toBeDefined();
      expect(row.hex, `name_fa bytes for ${row.code}`).toBe(
        Buffer.from(want as string, 'utf8').toString('hex'),
      );
    }
  });

  it('bitabar_app can read roles and user_roles but not write them; users is soft-delete only (U13/SR-05)', async () => {
    const result = await ownerPool().query<{ t: string; p: string; allowed: boolean }>(
      `SELECT t, p, has_table_privilege('bitabar_app', t::regclass, p) AS allowed
       FROM (VALUES
         ('roles', 'SELECT'), ('roles', 'INSERT'), ('roles', 'UPDATE'), ('roles', 'DELETE'),
         ('users', 'SELECT'), ('users', 'INSERT'), ('users', 'UPDATE'), ('users', 'DELETE'),
         ('user_roles', 'SELECT'), ('user_roles', 'INSERT'), ('user_roles', 'UPDATE'),
         ('user_roles', 'DELETE'), ('user_roles', 'TRUNCATE'),
         ('user_credentials', 'SELECT'), ('user_credentials', 'INSERT'), ('user_credentials', 'UPDATE'), ('user_credentials', 'DELETE'),
         ('auth_sessions', 'SELECT'), ('auth_sessions', 'INSERT'), ('auth_sessions', 'UPDATE'), ('auth_sessions', 'DELETE'),
         ('auth_rate_limits', 'SELECT'), ('auth_rate_limits', 'INSERT'), ('auth_rate_limits', 'UPDATE'), ('auth_rate_limits', 'DELETE'),
         ('audit_logs', 'SELECT'), ('audit_logs', 'INSERT'), ('audit_logs', 'UPDATE'),
         ('audit_logs', 'DELETE'), ('audit_logs', 'TRUNCATE'),
         ('idempotency_keys', 'SELECT'), ('idempotency_keys', 'INSERT'),
         ('idempotency_keys', 'UPDATE'), ('idempotency_keys', 'DELETE'),
         ('idempotency_keys', 'TRUNCATE')
       ) AS checks(t, p)
       ORDER BY t, p`,
    );
    expect(result.rows).toEqual([
      // Append-only (ADR-009 L3): reads and inserts only; no row/table rewrite.
      { t: 'audit_logs', p: 'DELETE', allowed: false },
      { t: 'audit_logs', p: 'INSERT', allowed: true },
      { t: 'audit_logs', p: 'SELECT', allowed: true },
      { t: 'audit_logs', p: 'TRUNCATE', allowed: false },
      { t: 'audit_logs', p: 'UPDATE', allowed: false },
      // Idempotency (ADR-010 L11): DELETE exists solely for the expired-row
      // sweep and is narrowed by the RESTRICTIVE policy; TRUNCATE never.
      { t: 'auth_rate_limits', p: 'DELETE', allowed: true }, // TTL sweep deletes expired counters
      { t: 'auth_rate_limits', p: 'INSERT', allowed: true },
      { t: 'auth_rate_limits', p: 'SELECT', allowed: true },
      { t: 'auth_rate_limits', p: 'UPDATE', allowed: true },
      { t: 'auth_sessions', p: 'DELETE', allowed: false }, // soft-revoke only (A9)
      { t: 'auth_sessions', p: 'INSERT', allowed: true },
      { t: 'auth_sessions', p: 'SELECT', allowed: true },
      { t: 'auth_sessions', p: 'UPDATE', allowed: true },
      { t: 'idempotency_keys', p: 'DELETE', allowed: true },
      { t: 'idempotency_keys', p: 'INSERT', allowed: true },
      { t: 'idempotency_keys', p: 'SELECT', allowed: true },
      { t: 'idempotency_keys', p: 'TRUNCATE', allowed: false },
      { t: 'idempotency_keys', p: 'UPDATE', allowed: true },
      { t: 'roles', p: 'DELETE', allowed: false },
      { t: 'roles', p: 'INSERT', allowed: false },
      { t: 'roles', p: 'SELECT', allowed: true },
      { t: 'roles', p: 'UPDATE', allowed: false },
      { t: 'user_credentials', p: 'DELETE', allowed: false }, // updated, never hard-deleted
      { t: 'user_credentials', p: 'INSERT', allowed: true },
      { t: 'user_credentials', p: 'SELECT', allowed: true },
      { t: 'user_credentials', p: 'UPDATE', allowed: true },
      // SR-05: reads stay, every direct write (including TRUNCATE) is gone.
      { t: 'user_roles', p: 'DELETE', allowed: false },
      { t: 'user_roles', p: 'INSERT', allowed: false },
      { t: 'user_roles', p: 'SELECT', allowed: true },
      { t: 'user_roles', p: 'TRUNCATE', allowed: false },
      { t: 'user_roles', p: 'UPDATE', allowed: false },
      { t: 'users', p: 'DELETE', allowed: false },
      { t: 'users', p: 'INSERT', allowed: true },
      { t: 'users', p: 'SELECT', allowed: true },
      { t: 'users', p: 'UPDATE', allowed: true },
    ]);
  });
});
