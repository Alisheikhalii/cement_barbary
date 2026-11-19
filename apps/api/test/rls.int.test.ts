import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { DomainError } from '../src/common/errors/domain-error.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import { createTenant, makeAppPool, ownerPool } from './setup/db.js';

/**
 * The core proof of tenant isolation (ADR-005 D1/D4/D6). A throwaway table
 * `rls_probe` is created as the schema OWNER inside this file and protected
 * with the exact RLS template from docs/security/rls.md — grants arrive via
 * ALTER DEFAULT PRIVILEGES from migration 0001, proving the template works for
 * future tables, not just `tenants`. Every scenario runs as the runtime role
 * bitabar_app (RLS applies); the owner is used only for setup and assertions
 * about setup.
 */
describe('RLS isolation suite (runtime role)', () => {
  const ctx = new TenantContext();
  let app: Pool;
  let tenantDb: TenantDb;
  let tenantA: string;
  let tenantB: string;
  let probeA: string;
  let probeB: string;

  beforeAll(async () => {
    const owner = ownerPool();
    await owner.query(`
      CREATE TABLE rls_probe (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants ON DELETE RESTRICT,
        label text NOT NULL
      );
    `);
    // The exact template from docs/security/rls.md:
    await owner.query('ALTER TABLE rls_probe ENABLE ROW LEVEL SECURITY;');
    await owner.query(`
      CREATE POLICY rls_probe_tenant_isolation ON rls_probe FOR ALL TO bitabar_app
        USING (tenant_id = (SELECT app.current_tenant_id()))
        WITH CHECK (tenant_id = (SELECT app.current_tenant_id()));
    `);
    tenantA = await createTenant(owner, `rls-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(owner, `rls-b-${uuidv7().slice(0, 8)}`);
    probeA = uuidv7();
    probeB = uuidv7();
    await owner.query(
      'INSERT INTO rls_probe (id, tenant_id, label) VALUES ($1, $2, $3), ($4, $5, $6)',
      [probeA, tenantA, 'row-a', probeB, tenantB, 'row-b'],
    );

    app = makeAppPool();
    tenantDb = new TenantDb(drizzle(app, { schema }));
  });

  afterAll(async () => {
    await app.end();
    await ownerPool().query('DROP TABLE IF EXISTS rls_probe');
  });

  /** Runs work as tenant `tenantId` through the enforced path (TenantContext + TenantDb). */
  function inTenant<T>(tenantId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    return ctx.run({ tenantId }, () => tenantDb.run(fn));
  }

  /** Walks drizzle's "Failed query" wrapper to the original pg error code. */
  function pgErrorCode(err: unknown): string | undefined {
    let cur: unknown = err;
    for (let i = 0; i < 5 && cur !== null && cur !== undefined; i++) {
      const code = (cur as { code?: unknown }).code;
      if (typeof code === 'string') {
        return code;
      }
      cur = (cur as { cause?: unknown }).cause;
    }
    return undefined;
  }

  /** Asserts the promise rejects and the underlying PostgreSQL error has `code`. */
  async function expectPgRejection(promise: Promise<unknown>, code: string): Promise<void> {
    const err = await promise.then(
      () => {
        throw new Error(`expected a rejection with pg code ${code}, but the query succeeded`);
      },
      (e: unknown) => e,
    );
    expect(pgErrorCode(err)).toBe(code);
  }

  it('role proof — every pooled connection is bitabar_app, never the owner', async () => {
    const res = await app.query('select current_user as u, session_user as s');
    expect(res.rows[0]).toEqual({ u: 'bitabar_app', s: 'bitabar_app' });
  });

  it('scenario 1 — no context: SELECT on rls_probe and tenants returns 0 rows (fail closed)', async () => {
    const probe = await app.query('select id from rls_probe');
    const tenants = await app.query('select id from tenants');
    expect(probe.rows).toHaveLength(0);
    expect(tenants.rows).toHaveLength(0);
  });

  it('scenario 2 — context A: raw SELECT * with no WHERE returns only A’s row', async () => {
    const rows = await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(sql`select * from rls_probe`);
      return res.rows as { id: string; tenant_id: string; label: string }[];
    });
    expect(rows).toEqual([{ id: probeA, tenant_id: tenantA, label: 'row-a' }]);
  });

  it('scenario 3 — context A: SELECT by B’s row id returns 0 rows (IDOR blocked at the DB)', async () => {
    const rows = await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(sql`select * from rls_probe where id = ${probeB}`);
      return res.rows;
    });
    expect(rows).toHaveLength(0);
  });

  it('scenario 4 — context A: INSERT with tenant_id = B is rejected (42501)', async () => {
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into rls_probe (id, tenant_id, label) values (${uuidv7()}, ${tenantB}, 'evil')`,
        );
      }),
      '42501',
    );
  });

  it('scenario 5 — context A: re-homing A’s row to tenant B via UPDATE is rejected (42501)', async () => {
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(sql`update rls_probe set tenant_id = ${tenantB} where id = ${probeA}`);
      }),
      '42501',
    );
  });

  it('scenario 6 — context A: UPDATE/DELETE on B’s row affect 0 rows and B stays intact', async () => {
    const { updated, deleted } = await inTenant(tenantA, async (tx) => {
      const u = await tx.execute(sql`update rls_probe set label = 'evil' where id = ${probeB}`);
      const d = await tx.execute(sql`delete from rls_probe where id = ${probeB}`);
      return { updated: u.rowCount, deleted: d.rowCount };
    });
    expect(updated).toBe(0);
    expect(deleted).toBe(0);
    const check = await ownerPool().query('select label from rls_probe where id = $1', [probeB]);
    expect((check.rows[0] as { label: string }).label).toBe('row-b');
  });

  it('scenario 7 — context A: tenants shows only A; INSERT/DELETE on tenants are denied', async () => {
    const visible = await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(sql`select id from tenants`);
      return (res.rows as { id: string }[]).map((r) => r.id);
    });
    expect(visible).toEqual([tenantA]);

    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into tenants (id, code, name) values (${uuidv7()}, 'evil', 'evil')`,
        );
      }),
      '42501',
    );

    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(sql`delete from tenants where id = ${tenantA}`);
      }),
      '42501',
    );
  });

  it('scenario 8 — runtime role cannot disable RLS, run DDL, create tables, or read migrations', async () => {
    // row_security = off must error on filtered queries, never leak rows:
    const client = await app.connect();
    try {
      await client.query('begin');
      await client.query('set local row_security = off');
      await expect(client.query('select * from rls_probe')).rejects.toThrow(/row-level security/i);
      await client.query('rollback');
    } finally {
      client.release();
    }

    await expect(
      app.query('alter table rls_probe disable row level security'),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(app.query('create table public.must_not_exist (id int)')).rejects.toMatchObject({
      code: '42501',
    });
    await expect(app.query('select * from drizzle.__drizzle_migrations')).rejects.toMatchObject({
      code: '42501',
    });
  });

  it('scenario 9 — a non-UUID app.tenant_id fails closed with an error, not data', async () => {
    const client = await app.connect();
    try {
      await client.query('begin');
      // set_config accepts any text; the uuid cast inside the policy must blow up:
      await client.query("select set_config('app.tenant_id', 'not-a-uuid', true)");
      await expect(client.query('select * from rls_probe')).rejects.toMatchObject({
        code: '22P02',
      });
      await client.query('rollback');
    } finally {
      client.release();
    }
  });

  it('scenario 10 — 100 parallel TenantDb.run calls on a 5-connection pool stay isolated', async () => {
    const small = makeAppPool({ max: 5 });
    const db = new TenantDb(drizzle(small, { schema }));
    try {
      const results = await Promise.all(
        Array.from({ length: 100 }, (_, i) => {
          const tenantId = i % 2 === 0 ? tenantA : tenantB;
          const expected = i % 2 === 0 ? probeA : probeB;
          return ctx.run({ tenantId }, () =>
            db.run(async (tx) => {
              const res = await tx.execute(sql`select id from rls_probe`);
              return { expected, ids: (res.rows as { id: string }[]).map((r) => r.id) };
            }),
          );
        }),
      );
      for (const r of results) {
        // Each run sees exactly its own tenant's row — zero cross-tenant results.
        expect(r.ids).toEqual([r.expected]);
      }
    } finally {
      await small.end();
    }
  });

  it('extra — a stale tx handle from tenant A throws inside tenant B’s transaction (cross-tenant leak closed)', async () => {
    // Pre-fix, this exact sequence returned [probeB]: A's stale handle executed
    // on the reused connection inside B's open transaction. The guarded handle
    // in TenantDb.run now throws before any SQL reaches the connection.
    const single = makeAppPool({ max: 1 });
    const db = new TenantDb(drizzle(single, { schema }));
    try {
      let stale: Tx | undefined;
      await ctx.run({ tenantId: tenantA }, () =>
        db.run(async (tx) => {
          stale = tx;
        }),
      );
      // A's transaction committed; the only pooled connection is free again.
      await ctx.run({ tenantId: tenantB }, () =>
        db.run(async () => {
          // B's transaction is open on that same physical connection.
          let err: unknown;
          try {
            await (stale as Tx).execute(sql`select id from rls_probe`);
          } catch (e) {
            err = e;
          }
          expect(err).toBeInstanceOf(DomainError);
          expect((err as DomainError).code).toBe('TENANT_CONTEXT_MISSING');
        }),
      );
      // The live path is unaffected: B's own run still sees exactly B's row.
      const rows = await ctx.run({ tenantId: tenantB }, () =>
        db.run(async (tx) => {
          const res = await tx.execute(sql`select id from rls_probe`);
          return (res.rows as { id: string }[]).map((r) => r.id);
        }),
      );
      expect(rows).toEqual([probeB]);
    } finally {
      await single.end();
    }
  });

  it('guard — every public table with a tenant_id column has RLS enabled and at least one policy', async () => {
    // Runs as the schema owner (catalog query; RLS is irrelevant here).
    // Exclusions: drizzle bookkeeping tables live in schema `drizzle`, outside
    // this query's scope (nspname = 'public'); `tenants` itself has no
    // tenant_id column and is covered by scenario 7 instead.
    const GUARD_SQL = `
      SELECT c.relname AS table_name,
             c.relrowsecurity AS rls_enabled,
             (SELECT count(*)::int FROM pg_policies p
               WHERE p.schemaname = 'public' AND p.tablename = c.relname) AS policy_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
        AND EXISTS (SELECT 1 FROM pg_attribute a
                     WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
    `;
    interface GuardRow {
      table_name: string;
      rls_enabled: boolean;
      policy_count: number;
    }
    const owner = ownerPool();

    // Negative control: a tenant_id table WITHOUT RLS must be flagged,
    // proving the guard is not vacuous.
    await owner.query('CREATE TABLE rls_guard_negative (id uuid, tenant_id uuid)');
    const flagged = (await owner.query(GUARD_SQL)).rows as GuardRow[];
    const negative = flagged.find((r) => r.table_name === 'rls_guard_negative');
    expect(negative).toMatchObject({ rls_enabled: false, policy_count: 0 });
    await owner.query('DROP TABLE rls_guard_negative');

    // Positive: every remaining tenant-owned table (incl. rls_probe) complies.
    const rows = (await owner.query(GUARD_SQL)).rows as GuardRow[];
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.map((r) => r.table_name)).toContain('rls_probe');
    for (const row of rows) {
      expect(row.rls_enabled).toBe(true);
      expect(row.policy_count).toBeGreaterThanOrEqual(1);
    }
  });

  it('extra — a tx handle kept after run() finished cannot read tenant data', async () => {
    let leaked: Tx | undefined;
    await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(async (tx) => {
        leaked = tx;
      }),
    );
    const handle = leaked as Tx;
    let rows: unknown[] | undefined;
    let threw = false;
    try {
      const res = await handle.execute(sql`select * from rls_probe`);
      rows = res.rows;
    } catch {
      threw = true;
    }
    // Two safe outcomes: the driver rejects the stale handle outright, or the
    // query runs after COMMIT — where the transaction-local app.tenant_id has
    // reverted and RLS hides every row. Any tenant data here fails the test.
    // (Observed with pg 8: no throw — query-after-release is not guarded by
    // the driver — but the reverted setting yields zero rows.)
    if (!threw) {
      expect(rows).toEqual([]);
    }
    expect(rows ?? []).toHaveLength(0);
  });
});
