import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { DomainError } from '../src/common/errors/domain-error.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import {
  assignRole,
  createTenant,
  createUser,
  createUserWithPhoneHash,
  makeAppPool,
  ownerPool,
  testPii,
} from './setup/db.js';

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
  let userA: string;
  let userB: string;
  let userADeletable: string;
  let userASoftDelete: string;

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

    // F1-03 fixtures: one user per tenant (phone via the real PII path,
    // synthetic allowlisted numbers only, U17) plus role links.
    userA = await createUser(owner, tenantA, { username: 'user.a', phone: '09120000001' });
    userB = await createUser(owner, tenantB, { username: 'user.b', phone: '09120000002' });
    userADeletable = await createUser(owner, tenantA, { phone: '09120000003' });
    userASoftDelete = await createUser(owner, tenantA, { phone: '09120000004' });
    await assignRole(owner, tenantA, userA, 'FACTORY_OPERATOR', 'tenant');
    await assignRole(owner, tenantB, userB, 'DRIVER', 'driver');
    await assignRole(owner, tenantA, userADeletable, 'DRIVER', 'driver');

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

  it('guard (U14) — every public table is tenant-owned with RLS or on the allowlist with a reason', async () => {
    // Runs as the schema owner (catalog query; RLS is irrelevant here).
    // The allowlist is explicit and every entry carries a written reason
    // (change (f)); drizzle bookkeeping lives in schema `drizzle`, outside
    // this query's scope.
    const ALLOWLIST = new Map([
      ['tenants', 'platform-owned tenant registry; the row IS the tenant (RLS on id, F1-02)'],
      ['roles', 'global read-only role catalog; bitabar_app has SELECT only (ADR-006 U1)'],
    ]);
    for (const [table, reason] of ALLOWLIST) {
      expect(reason.length, `allowlist entry ${table} needs a written reason`).toBeGreaterThan(0);
    }

    const GUARD_SQL = `
      SELECT c.relname AS table_name,
             c.relrowsecurity AS rls_enabled,
             EXISTS (SELECT 1 FROM pg_attribute a
                      WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
                        AND NOT a.attisdropped) AS has_tenant_id,
             (SELECT count(*)::int FROM pg_policies p
               WHERE p.schemaname = 'public' AND p.tablename = c.relname) AS policy_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
    `;
    interface GuardRow {
      table_name: string;
      rls_enabled: boolean;
      has_tenant_id: boolean;
      policy_count: number;
    }
    const violations = (rows: GuardRow[]) =>
      rows
        .filter((r) => !ALLOWLIST.has(r.table_name))
        .filter((r) => !(r.has_tenant_id && r.rls_enabled && r.policy_count >= 1))
        .map((r) => r.table_name);
    const owner = ownerPool();

    // Negative controls: a tenant_id table WITHOUT RLS, and a table with NO
    // tenant_id that is not allowlisted — both must be flagged, proving the
    // guard is not vacuous.
    await owner.query('CREATE TABLE rls_guard_negative (id uuid, tenant_id uuid)');
    await owner.query('CREATE TABLE rls_guard_stray (id uuid)');
    const flagged = violations((await owner.query(GUARD_SQL)).rows as GuardRow[]);
    expect(flagged).toContain('rls_guard_negative');
    expect(flagged).toContain('rls_guard_stray');
    await owner.query('DROP TABLE rls_guard_negative');
    await owner.query('DROP TABLE rls_guard_stray');

    // Positive: with the controls gone, nothing violates; the allowlist is
    // exactly the set of public tables without tenant_id (no more, no less).
    const rows = (await owner.query(GUARD_SQL)).rows as GuardRow[];
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.map((r) => r.table_name)).toContain('rls_probe');
    expect(violations(rows)).toEqual([]);
    expect(
      rows
        .filter((r) => !r.has_tenant_id)
        .map((r) => r.table_name)
        .sort(),
    ).toEqual([...ALLOWLIST.keys()].sort());
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

  // ---------- F1-03 T05: users / user_roles / roles (ADR-006) ----------

  it('users + user_roles — no context returns 0 rows from both (fail closed)', async () => {
    const users = await app.query('select id from users');
    const links = await app.query('select user_id from user_roles');
    expect(users.rows).toHaveLength(0);
    expect(links.rows).toHaveLength(0);
  });

  it('users — context A sees only A’s users; B’s id and B’s phone_hash return 0 rows (IDOR)', async () => {
    const bHash = (
      await ownerPool().query<{ phone_hash: Buffer }>(
        'select phone_hash from users where id = $1',
        [userB],
      )
    ).rows[0]?.phone_hash as Buffer;

    await inTenant(tenantA, async (tx) => {
      const visible = await tx.execute(sql`select id, tenant_id from users`);
      const rows = visible.rows as { id: string; tenant_id: string }[];
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.map((r) => r.id)).toContain(userA);
      expect(rows.map((r) => r.id)).not.toContain(userB);
      expect(rows.every((r) => r.tenant_id === tenantA)).toBe(true);

      const byId = await tx.execute(sql`select id from users where id = ${userB}`);
      expect(byId.rows).toHaveLength(0);

      const byHash = await tx.execute(sql`select id from users where phone_hash = ${bHash}`);
      expect(byHash.rows).toHaveLength(0);
    });
  });

  it('users — context A cannot insert for tenant B nor re-home a row to B (42501)', async () => {
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into users (id, tenant_id, display_name, username)
              values (${uuidv7()}, ${tenantB}, 'Evil', 'evil.user')`,
        );
      }),
      '42501',
    );
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(sql`update users set tenant_id = ${tenantB} where id = ${userA}`);
      }),
      '42501',
    );
  });

  it('users — context A: updating B’s row affects 0 rows and B stays intact', async () => {
    const updated = await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(sql`update users set display_name = 'evil' where id = ${userB}`);
      return res.rowCount;
    });
    expect(updated).toBe(0);
    const check = await ownerPool().query('select display_name from users where id = $1', [userB]);
    expect((check.rows[0] as { display_name: string }).display_name).toBe('Test User');
  });

  it('users — hard DELETE is denied even in own tenant (U13); soft delete via UPDATE works', async () => {
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(sql`delete from users where id = ${userASoftDelete}`);
      }),
      '42501',
    );
    const updated = await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(
        sql`update users set deleted_at = now() where id = ${userASoftDelete}`,
      );
      return res.rowCount;
    });
    expect(updated).toBe(1);
    const check = await ownerPool().query('select deleted_at from users where id = $1', [
      userASoftDelete,
    ]);
    expect((check.rows[0] as { deleted_at: Date | null }).deleted_at).not.toBeNull();
  });

  it('user_roles — context A sees only A’s links; deleting B’s link affects 0 rows; own delete works', async () => {
    await inTenant(tenantA, async (tx) => {
      const visible = await tx.execute(sql`select tenant_id, user_id, role_code from user_roles`);
      const rows = visible.rows as { tenant_id: string; user_id: string; role_code: string }[];
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => r.tenant_id === tenantA)).toBe(true);
      expect(rows.map((r) => r.user_id)).not.toContain(userB);

      const denied = await tx.execute(sql`delete from user_roles where user_id = ${userB}`);
      expect(denied.rowCount).toBe(0);

      const own = await tx.execute(
        sql`delete from user_roles where user_id = ${userADeletable} and role_code = 'DRIVER'`,
      );
      expect(own.rowCount).toBe(1);
    });
    const check = await ownerPool().query(
      'select count(*)::int as n from user_roles where user_id = $1',
      [userB],
    );
    expect(check.rows[0]?.n).toBe(1);
  });

  it('user_roles — cross-tenant link, platform role, forged scope and RLS write-check are all rejected', async () => {
    // (a) Link to B's user from tenant A: WITH CHECK passes (tenant A) but the
    // composite FK (tenant_id, user_id) -> users has no such pair → 23503.
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into user_roles (tenant_id, user_id, role_code, role_scope)
              values (${tenantA}, ${userB}, 'DRIVER', 'driver')`,
        );
      }),
      '23503',
    );
    // (b) Platform scope: 'PLATFORM_ADMIN' no longer exists in the catalog
    // (removed in 0004, T05b), but PostgreSQL evaluates CHECK constraints
    // before the AFTER ROW triggers that enforce FKs — so the CHECK
    // (role_scope <> 'platform') is still what fires → 23514, as the app AND
    // as the owner (the CHECK holds even for the role that bypasses RLS).
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into user_roles (tenant_id, user_id, role_code, role_scope)
              values (${tenantA}, ${userA}, 'PLATFORM_ADMIN', 'platform')`,
        );
      }),
      '23514',
    );
    await expectPgRejection(
      ownerPool().query(
        `insert into user_roles (tenant_id, user_id, role_code, role_scope)
         values ($1, $2, 'PLATFORM_ADMIN', 'platform')`,
        [tenantA, userA],
      ),
      '23514',
    );
    // (c) Forged scope for a real role: DRIVER exists with scope 'driver', so
    // the pair ('DRIVER','carrier') is not in roles → composite FK violation
    // 23503. The scope cannot lie. (DRIVER is used because userA holds no
    // DRIVER link — a held role would hit the PK first and prove nothing
    // about the FK.)
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into user_roles (tenant_id, user_id, role_code, role_scope)
              values (${tenantA}, ${userA}, 'DRIVER', 'carrier')`,
        );
      }),
      '23503',
    );
    // (d) A link row carrying tenant B's id, inserted from context A → RLS
    // WITH CHECK rejects it → 42501.
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into user_roles (tenant_id, user_id, role_code, role_scope)
              values (${tenantB}, ${userB}, 'DRIVER', 'driver')`,
        );
      }),
      '42501',
    );
  });

  it('roles — globally readable; INSERT/UPDATE/DELETE denied for the runtime role', async () => {
    const listed = await app.query('select code from roles');
    expect(listed.rows).toHaveLength(3);
    await expect(
      app.query(`insert into roles (code, name_fa, scope) values ('X', 'x', 'tenant')`),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      app.query(`update roles set description = 'x' where code = 'DRIVER'`),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(app.query(`delete from roles where code = 'DRIVER'`)).rejects.toMatchObject({
      code: '42501',
    });
  });

  it('users — phone_hash uniqueness is per tenant, never global; reusable after soft delete', async () => {
    const owner = ownerPool();
    // Same hash bytes in two tenants: allowed (change (d) — per-tenant index).
    const sharedHash = Buffer.alloc(32, 7);
    const firstA = await createUserWithPhoneHash(owner, tenantA, sharedHash);
    await createUserWithPhoneHash(owner, tenantB, sharedHash);

    // Same hash again inside tenant A: rejected (23505) — as the runtime role.
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into users (id, tenant_id, display_name, phone_enc, phone_hash)
              values (${uuidv7()}, ${tenantA}, 'Dup', ${Buffer.from([9])}, ${sharedHash})`,
        );
      }),
      '23505',
    );

    // After soft-deleting the first row, the hash is free again in tenant A
    // (partial unique index WHERE deleted_at IS NULL).
    await owner.query('update users set deleted_at = now() where id = $1', [firstA]);
    await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(
        sql`insert into users (id, tenant_id, display_name, phone_enc, phone_hash)
            values (${uuidv7()}, ${tenantA}, 'Reused', ${Buffer.from([9])}, ${sharedHash})`,
      );
      expect(res.rowCount).toBe(1);
    });

    // U8 end-to-end: the same phone yields different blind-index hashes in A and B.
    const hA = testPii().blindIndex('phone', tenantA, '09120000009');
    const hB = testPii().blindIndex('phone', tenantB, '09120000009');
    expect(hA.equals(hB)).toBe(false);
  });

  it('users — U12 CHECKs reject bad rows (login present, enc/hash pairs)', async () => {
    // No username and no phone_hash → users_login_present.
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into users (id, tenant_id, display_name)
              values (${uuidv7()}, ${tenantA}, 'No Login')`,
        );
      }),
      '23514',
    );
    // phone_hash without phone_enc → users_phone_pair.
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into users (id, tenant_id, display_name, phone_hash)
              values (${uuidv7()}, ${tenantA}, 'Half Pair', ${Buffer.alloc(32, 8)})`,
        );
      }),
      '23514',
    );
    // national_id_hash without national_id_enc → users_national_id_pair
    // (username present so only the pair CHECK can fire).
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`insert into users (id, tenant_id, display_name, username, national_id_hash)
              values (${uuidv7()}, ${tenantA}, 'Half Pair 2', 'half.pair', ${Buffer.alloc(32, 10)})`,
        );
      }),
      '23514',
    );
  });

  it('users — national-ID columns stay NULL for every row (owner Q3; no write path exists in F1-03)', async () => {
    // The rejected CHECK attempts above prove violations are blocked; this
    // proves nothing — fixture or code — ever wrote a national ID. T07
    // re-asserts this after the dev seed runs.
    const res = await ownerPool().query<{ n: number }>(
      'select count(*)::int as n from users where national_id_enc is not null or national_id_hash is not null',
    );
    expect(res.rows[0]?.n).toBe(0);
  });
});
