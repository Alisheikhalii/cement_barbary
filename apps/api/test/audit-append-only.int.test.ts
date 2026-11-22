import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import { createTenant, createUser, makeAppPool, ownerPool } from './setup/db.js';

/**
 * audit_logs invariants on a real PostgreSQL 17 (ADR-009 L3, owner CP1 A3):
 * RLS isolation, append-only for the runtime role AND the owner (trigger),
 * server-forced occurred_at, and the size/actor constraints.
 */
describe('audit_logs append-only (integration)', () => {
  const ctx = new TenantContext();
  let app: Pool;
  let tenantDb: TenantDb;
  let tenantA: string;
  let tenantB: string;
  let userA: string;
  let userB: string;

  beforeAll(async () => {
    const owner = ownerPool();
    tenantA = await createTenant(owner, `audit-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(owner, `audit-b-${uuidv7().slice(0, 8)}`);
    userA = await createUser(owner, tenantA, { username: 'audit.a', phone: '09120000005' });
    userB = await createUser(owner, tenantB, { username: 'audit.b', phone: '09120000006' });
    app = makeAppPool();
    tenantDb = new TenantDb(drizzle(app, { schema }));
  });

  afterAll(async () => {
    await app.end();
  });

  function inTenant<T>(tenantId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    return ctx.run({ tenantId }, () => tenantDb.run(fn));
  }

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

  async function expectPgRejection(promise: Promise<unknown>, code: string): Promise<void> {
    const err = await promise.then(
      () => {
        throw new Error(`expected a rejection with pg code ${code}, but the query succeeded`);
      },
      (e: unknown) => e,
    );
    expect(pgErrorCode(err)).toBe(code);
  }

  /**
   * Incompressible text: repeated uuidv7 hex is high-entropy, so the stored
   * jsonb cannot be shrunk by compression. `octet_length(col::text)` counts
   * these characters exactly, which is the cap the owner asked for at CP2.
   */
  function randomText(length: number): string {
    let out = '';
    while (out.length < length) {
      out += uuidv7().replaceAll('-', '');
    }
    return out.slice(0, length);
  }

  async function insertRow(tenantId: string, actorUserId: string, occurredAt?: string) {
    return inTenant(tenantId, async (tx) => {
      const result = await tx.execute(sql`
        INSERT INTO audit_logs
          (id, tenant_id, actor_type, actor_user_id, action, resource_type, resource_id, outcome,
           http_status, reason, occurred_at)
        VALUES (${uuidv7()}, ${tenantId}, 'user', ${actorUserId}, 'user.role.assigned', 'user',
                ${actorUserId}, 'success', 200, 'integration test reason',
                ${occurredAt ?? null})
        RETURNING id, occurred_at
      `);
      return result.rows[0] as { id: string; occurred_at: Date };
    });
  }

  it('no context sees zero rows even when rows exist (fail closed)', async () => {
    // The row makes this non-vacuous: without it the test would pass even if
    // RLS were missing entirely.
    await insertRow(tenantA, userA);
    const result = await app.query('SELECT count(*)::int AS n FROM audit_logs');
    expect(result.rows[0]?.n).toBe(0);
  });

  it('an INSERT without a tenant context is rejected (42501)', async () => {
    await expectPgRejection(
      app.query(
        `
        INSERT INTO audit_logs
          (id, tenant_id, actor_type, action, resource_type, outcome)
        VALUES ($1, $2, 'system', 'user.role.assigned', 'user', 'success')
      `,
        [uuidv7(), tenantA],
      ),
      '42501',
    );
  });

  it('forces occurred_at to the server clock even when an old value is supplied (A3)', async () => {
    const before = Date.now();
    const row = await insertRow(tenantA, userA, '2000-01-01T00:00:00Z');
    const stored = new Date(row.occurred_at).getTime();
    expect(stored).toBeGreaterThanOrEqual(before - 1000);
    expect(Date.now() - stored).toBeLessThan(60_000);
  });

  it('context A sees only A rows; B’s row is invisible (IDOR at the DB)', async () => {
    const rowA = await insertRow(tenantA, userA);
    const rowB = await insertRow(tenantB, userB);
    const seenByA = await inTenant(tenantA, (tx) =>
      tx.execute(sql`SELECT id FROM audit_logs WHERE id = ${rowB.id}`),
    );
    expect(seenByA.rows).toEqual([]);
    const countA = await inTenant(tenantA, (tx) =>
      tx.execute(sql`SELECT count(*)::int AS n FROM audit_logs`),
    );
    expect((countA.rows[0] as { n: number }).n).toBeGreaterThan(0);
    const ownRow = await inTenant(tenantA, (tx) =>
      tx.execute(sql`SELECT id FROM audit_logs WHERE id = ${rowA.id}`),
    );
    expect(ownRow.rows).toHaveLength(1);
  });

  it('rejects a cross-tenant INSERT under context A (42501)', async () => {
    await expectPgRejection(
      inTenant(tenantA, (tx) =>
        tx.execute(sql`
          INSERT INTO audit_logs
            (id, tenant_id, actor_type, action, resource_type, outcome)
          VALUES (${uuidv7()}, ${tenantB}, 'system', 'user.role.assigned', 'user', 'success')
        `),
      ),
      '42501',
    );
  });

  it('rejects a cross-tenant actor even in the caller’s own tenant (composite FK, 23503)', async () => {
    await expectPgRejection(insertRow(tenantA, userB), '23503');
  });

  it('the runtime role cannot UPDATE, DELETE or TRUNCATE (42501)', async () => {
    const row = await insertRow(tenantA, userA);
    await expectPgRejection(
      inTenant(tenantA, (tx) =>
        tx.execute(sql`UPDATE audit_logs SET reason = 'rewritten' WHERE id = ${row.id}`),
      ),
      '42501',
    );
    await expectPgRejection(
      inTenant(tenantA, (tx) => tx.execute(sql`DELETE FROM audit_logs WHERE id = ${row.id}`)),
      '42501',
    );
    await expectPgRejection(
      inTenant(tenantA, (tx) => tx.execute(sql`TRUNCATE audit_logs`)),
      '42501',
    );
  });

  it('even the migration owner cannot rewrite history — the triggers block every role', async () => {
    const row = await insertRow(tenantA, userA);
    const owner = ownerPool();
    await expectPgRejection(
      owner.query("UPDATE audit_logs SET reason = 'rewritten' WHERE id = $1", [row.id]),
      '42501',
    );
    await expectPgRejection(owner.query('DELETE FROM audit_logs WHERE id = $1', [row.id]), '42501');
    await expectPgRejection(owner.query('TRUNCATE audit_logs'), '42501');
  });

  it('enforces the constraint set (actor pair, reason length, json size, action format, ip pair)', async () => {
    const insert = (extraSql: ReturnType<typeof sql>) =>
      inTenant(tenantA, (tx) => tx.execute(extraSql));
    const base = (
      actorType: string,
      actorId: string | null,
      action: string,
      reason: string | null,
      metadata: string | null,
      ip: boolean,
    ) => sql`
      INSERT INTO audit_logs
        (id, tenant_id, actor_type, actor_user_id, action, resource_type, outcome, reason, metadata,
         ip_enc, ip_hash)
      VALUES (${uuidv7()}, ${tenantA}, ${actorType}, ${actorId}, ${action}, 'user', 'success',
              ${reason}, ${metadata}::jsonb, ${ip ? Buffer.from([1, 2, 3]) : null},
              ${ip ? Buffer.from([4, 5, 6]) : null})
    `;

    await expectPgRejection(
      insert(base('user', null, 'user.role.assigned', null, null, false)),
      '23514',
    );
    await expectPgRejection(
      insert(base('system', null, 'not a valid action', null, null, false)),
      '23514',
    );
    await expectPgRejection(
      insert(base('system', null, 'user.role.assigned', 'x'.repeat(501), null, false)),
      '23514',
    );
    // A highly compressible payload above the logical cap is still rejected:
    // the CHECK counts `octet_length(col::text)`, not the compressed on-disk
    // size (`pg_column_size`), which would have let this one through.
    await expectPgRejection(
      insert(
        base(
          'system',
          null,
          'user.role.assigned',
          null,
          JSON.stringify({ blob: 'x'.repeat(17_000) }),
          false,
        ),
      ),
      '23514',
    );
    // Incompressible payload above the cap is rejected too.
    await expectPgRejection(
      insert(
        base(
          'system',
          null,
          'user.role.assigned',
          null,
          JSON.stringify({ blob: randomText(17_000) }),
          false,
        ),
      ),
      '23514',
    );
    // The same shape just below the cap is accepted, so the check is a cap and
    // not an accidental ban on `metadata`.
    await insert(
      base(
        'system',
        null,
        'user.role.assigned',
        null,
        JSON.stringify({ blob: randomText(8_000) }),
        false,
      ),
    );
    await expectPgRejection(
      inTenant(tenantA, (tx) =>
        tx.execute(sql`
          INSERT INTO audit_logs
            (id, tenant_id, actor_type, action, resource_type, outcome, ip_enc)
          VALUES (${uuidv7()}, ${tenantA}, 'system', 'user.role.assigned', 'user', 'success',
                  ${Buffer.from([1, 2, 3])})
        `),
      ),
      '23514',
    );
  });

  it('enforces the enum, status, before-size and IP bounds', async () => {
    const raw = (query: ReturnType<typeof sql>) => inTenant(tenantA, (tx) => tx.execute(query));
    const baseInsert = (columns: string, values: ReturnType<typeof sql>) =>
      sql`INSERT INTO audit_logs (id, tenant_id, actor_type, action, resource_type, outcome, ${sql.raw(columns)})
          VALUES (${uuidv7()}, ${tenantA}, 'system', 'user.role.assigned', 'user', 'success', ${values})`;

    await expectPgRejection(
      raw(sql`
        INSERT INTO audit_logs (id, tenant_id, actor_type, action, resource_type, outcome)
        VALUES (${uuidv7()}, ${tenantA}, 'system', 'user.role.assigned', 'user', 'nope')
      `),
      '23514',
    );
    await expectPgRejection(
      raw(sql`
        INSERT INTO audit_logs
          (id, tenant_id, actor_type, action, resource_type, outcome, http_status)
        VALUES (${uuidv7()}, ${tenantA}, 'system', 'user.role.assigned', 'user', 'success', 600)
      `),
      '23514',
    );
    await expectPgRejection(
      raw(sql`
        INSERT INTO audit_logs (id, tenant_id, actor_type, action, resource_type, outcome)
        VALUES (${uuidv7()}, ${tenantA}, 'robot', 'user.role.assigned', 'user', 'success')
      `),
      '23514',
    );
    await expectPgRejection(
      raw(baseInsert('before', sql`${JSON.stringify({ blob: randomText(17_000) })}::jsonb`)),
      '23514',
    );
    // `after` gets the compressible variant: both columns use the same exact
    // logical cap.
    await expectPgRejection(
      raw(baseInsert('after', sql`${JSON.stringify({ blob: 'x'.repeat(17_000) })}::jsonb`)),
      '23514',
    );
    await expectPgRejection(
      raw(baseInsert('ip_enc, ip_hash', sql`${Buffer.alloc(1025)}, ${Buffer.alloc(32)}`)),
      '23514',
    );
    await expectPgRejection(
      raw(baseInsert('ip_enc, ip_hash', sql`${Buffer.alloc(16)}, ${Buffer.alloc(31)}`)),
      '23514',
    );
    // The bounds allow a real value: bounded ciphertext + a 32-byte index.
    await raw(baseInsert('ip_enc, ip_hash', sql`${Buffer.alloc(48)}, ${Buffer.alloc(32)}`));
  });

  it('keeps the trigger functions SECURITY INVOKER and all three triggers present', async () => {
    const result = await ownerPool().query<{ proname: string; prosecdef: boolean }>(
      `SELECT p.proname, p.prosecdef
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'app'
          AND p.proname IN ('audit_logs_block_mutation', 'audit_logs_force_occurred_at')
        ORDER BY p.proname`,
    );
    expect(result.rows).toEqual([
      { proname: 'audit_logs_block_mutation', prosecdef: false },
      { proname: 'audit_logs_force_occurred_at', prosecdef: false },
    ]);
    // Owner CP2: all three triggers must be enabled (`tgenabled = 'O'`). A
    // replica-only ('R') or disabled ('D') trigger would silently drop the
    // append-only / occurred_at guarantees.
    const triggers = await ownerPool().query<{ tgname: string; tgenabled: string }>(
      `SELECT t.tgname, t.tgenabled
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
        WHERE c.relname = 'audit_logs' AND c.relnamespace = 'public'::regnamespace
          AND NOT t.tgisinternal
        ORDER BY t.tgname`,
    );
    expect(triggers.rows).toEqual([
      { tgname: 'audit_logs_force_occurred_at', tgenabled: 'O' },
      { tgname: 'audit_logs_no_mutation', tgenabled: 'O' },
      { tgname: 'audit_logs_no_truncate', tgenabled: 'O' },
    ]);

    // Both functions are pinned; an unpinned trigger function could resolve
    // `clock_timestamp` or `RAISE` through a shadowing schema.
    const pinned = await ownerPool().query<{ proname: string; proconfig: string[] | null }>(
      `SELECT p.proname, p.proconfig
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'app'
          AND p.proname IN ('audit_logs_block_mutation', 'audit_logs_force_occurred_at')
        ORDER BY p.proname`,
    );
    expect(pinned.rows).toEqual([
      { proname: 'audit_logs_block_mutation', proconfig: ['search_path=pg_catalog, pg_temp'] },
      { proname: 'audit_logs_force_occurred_at', proconfig: ['search_path=pg_catalog, pg_temp'] },
    ]);

    // The runtime role holds no privilege that could create a competing
    // trigger or FK (the migration post-condition also asserts this).
    const privileges = await ownerPool().query<{
      update: boolean;
      delete: boolean;
      truncate: boolean;
      trigger: boolean;
      references: boolean;
    }>(
      `SELECT has_table_privilege('bitabar_app', 'public.audit_logs', 'UPDATE') AS update,
              has_table_privilege('bitabar_app', 'public.audit_logs', 'DELETE') AS delete,
              has_table_privilege('bitabar_app', 'public.audit_logs', 'TRUNCATE') AS truncate,
              has_table_privilege('bitabar_app', 'public.audit_logs', 'TRIGGER') AS trigger,
              has_table_privilege('bitabar_app', 'public.audit_logs', 'REFERENCES') AS references`,
    );
    expect(privileges.rows[0]).toEqual({
      update: false,
      delete: false,
      truncate: false,
      trigger: false,
      references: false,
    });
  });
});
