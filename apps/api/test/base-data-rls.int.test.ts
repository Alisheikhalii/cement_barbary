import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import { createTenant, makeAppPool, ownerPool } from './setup/db.js';

/**
 * RLS and privilege proof for the five base-data tables (F1-07 T03): the
 * template is applied, writes are tenant-scoped, and the runtime role can
 * soft-delete but never hard-delete. Fixtures are inserted as the schema
 * owner; every assertion runs as bitabar_app through the enforced
 * TenantContext + TenantDb path.
 */
describe('base data RLS and privileges (runtime role)', () => {
  const ctx = new TenantContext();
  let app: Pool;
  let tenantDb: TenantDb;
  let tenantA: string;
  let tenantB: string;
  let destA: string;
  let destB: string;
  let hallA: string;
  let hallB: string;
  let termA: string;
  let termB: string;
  let groupA: string;
  let groupB: string;
  let typeA: string;
  let typeB: string;

  const TABLES = ['destinations', 'halls', 'hall_terminals', 'loader_type_groups', 'loader_types'];

  beforeAll(async () => {
    const owner = ownerPool();
    tenantA = await createTenant(owner, `rls-base-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(owner, `rls-base-b-${uuidv7().slice(0, 8)}`);

    destA = uuidv7();
    destB = uuidv7();
    hallA = uuidv7();
    hallB = uuidv7();
    termA = uuidv7();
    termB = uuidv7();
    groupA = uuidv7();
    groupB = uuidv7();
    typeA = uuidv7();
    typeB = uuidv7();

    await owner.query(
      `INSERT INTO destinations (id, tenant_id, name, name_key)
       VALUES ($1, $2, 'Dest A', 'dest a'), ($3, $4, 'Dest B', 'dest b')`,
      [destA, tenantA, destB, tenantB],
    );
    await owner.query(
      `INSERT INTO halls (id, tenant_id, name, name_key)
       VALUES ($1, $2, 'Hall A', 'hall a'), ($3, $4, 'Hall B', 'hall b')`,
      [hallA, tenantA, hallB, tenantB],
    );
    await owner.query(
      `INSERT INTO hall_terminals (id, tenant_id, hall_id, name, name_key)
       VALUES ($1, $2, $3, 'Term A', 'term a'), ($4, $5, $6, 'Term B', 'term b')`,
      [termA, tenantA, hallA, termB, tenantB, hallB],
    );
    await owner.query(
      `INSERT INTO loader_type_groups (id, tenant_id, name, name_key)
       VALUES ($1, $2, 'Group A', 'group a'), ($3, $4, 'Group B', 'group b')`,
      [groupA, tenantA, groupB, tenantB],
    );
    await owner.query(
      `INSERT INTO loader_types (id, tenant_id, group_id, name, name_key)
       VALUES ($1, $2, $3, 'Type A', 'type a'), ($4, $5, $6, 'Type B', 'type b')`,
      [typeA, tenantA, groupA, typeB, tenantB, groupB],
    );

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
    let current: unknown = err;
    for (let i = 0; i < 5 && current !== null && current !== undefined; i++) {
      const code = (current as { code?: unknown }).code;
      if (typeof code === 'string') {
        return code;
      }
      current = (current as { cause?: unknown }).cause;
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

  it('no context: all five tables return zero rows (fail closed)', async () => {
    for (const table of TABLES) {
      const res = await app.query(`SELECT id FROM ${table}`);
      expect(res.rows, table).toHaveLength(0);
    }
  });

  it('context A: raw SELECT * on each table returns only A’s rows', async () => {
    const expected: Record<string, string> = {
      destinations: destA,
      halls: hallA,
      hall_terminals: termA,
      loader_type_groups: groupA,
      loader_types: typeA,
    };
    await inTenant(tenantA, async (tx) => {
      for (const table of TABLES) {
        const res = await tx.execute(sql.raw(`SELECT id, tenant_id FROM ${table}`));
        const rows = res.rows as { id: string; tenant_id: string }[];
        expect(
          rows.map((r) => r.id),
          table,
        ).toEqual([expected[table]]);
        expect(
          rows.every((r) => r.tenant_id === tenantA),
          table,
        ).toBe(true);
      }
    });
  });

  it('context A: B’s ids return zero rows on every table (IDOR blocked)', async () => {
    const idsB: Record<string, string> = {
      destinations: destB,
      halls: hallB,
      hall_terminals: termB,
      loader_type_groups: groupB,
      loader_types: typeB,
    };
    await inTenant(tenantA, async (tx) => {
      for (const table of TABLES) {
        const res = await tx.execute(
          sql.raw(`SELECT id FROM ${table} WHERE id = '${idsB[table]}'::uuid`),
        );
        expect(res.rows, table).toHaveLength(0);
      }
    });
  });

  it('context A: INSERT with tenant_id = B is rejected on every table (42501)', async () => {
    const inserts: Record<string, () => Promise<unknown>> = {
      destinations: () =>
        inTenant(tenantA, async (tx) => {
          await tx.execute(
            sql`INSERT INTO destinations (id, tenant_id, name, name_key)
                VALUES (${uuidv7()}, ${tenantB}, 'Evil', ${`evil-d-${uuidv7()}`})`,
          );
        }),
      halls: () =>
        inTenant(tenantA, async (tx) => {
          await tx.execute(
            sql`INSERT INTO halls (id, tenant_id, name, name_key)
                VALUES (${uuidv7()}, ${tenantB}, 'Evil', ${`evil-h-${uuidv7()}`})`,
          );
        }),
      hall_terminals: () =>
        inTenant(tenantA, async (tx) => {
          await tx.execute(
            sql`INSERT INTO hall_terminals (id, tenant_id, hall_id, name, name_key)
                VALUES (${uuidv7()}, ${tenantB}, ${hallA}, 'Evil', ${`evil-t-${uuidv7()}`})`,
          );
        }),
      loader_type_groups: () =>
        inTenant(tenantA, async (tx) => {
          await tx.execute(
            sql`INSERT INTO loader_type_groups (id, tenant_id, name, name_key)
                VALUES (${uuidv7()}, ${tenantB}, 'Evil', ${`evil-g-${uuidv7()}`})`,
          );
        }),
      loader_types: () =>
        inTenant(tenantA, async (tx) => {
          await tx.execute(
            sql`INSERT INTO loader_types (id, tenant_id, group_id, name, name_key)
                VALUES (${uuidv7()}, ${tenantB}, ${groupA}, 'Evil', ${`evil-lt-${uuidv7()}`})`,
          );
        }),
    };
    for (const table of TABLES) {
      const insert = inserts[table];
      if (!insert) {
        throw new Error(`missing insert fixture for ${table}`);
      }
      await expectPgRejection(insert(), '42501');
    }
  });

  it('context A: re-homing a row to B is rejected (42501); B’s row is untouched', async () => {
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(sql`UPDATE destinations SET tenant_id = ${tenantB} WHERE id = ${destA}`);
      }),
      '42501',
    );
    const updated = await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(sql`UPDATE destinations SET name = 'evil' WHERE id = ${destB}`);
      return res.rowCount;
    });
    expect(updated).toBe(0);
    const check = await ownerPool().query('SELECT name FROM destinations WHERE id = $1', [destB]);
    expect((check.rows[0] as { name: string }).name).toBe('Dest B');
  });

  it('context A: soft delete via UPDATE works; hard DELETE and TRUNCATE are 42501 on all five', async () => {
    const spare = uuidv7();
    await ownerPool().query(
      `INSERT INTO destinations (id, tenant_id, name, name_key)
       VALUES ($1, $2, 'Spare', $3)`,
      [spare, tenantA, `spare-${uuidv7()}`],
    );
    const softDeleted = await inTenant(tenantA, async (tx) => {
      const res = await tx.execute(
        sql`UPDATE destinations SET deleted_at = now(), version = version + 1 WHERE id = ${spare}`,
      );
      return res.rowCount;
    });
    expect(softDeleted).toBe(1);

    for (const table of TABLES) {
      await expectPgRejection(
        inTenant(tenantA, async (tx) => {
          await tx.execute(sql.raw(`DELETE FROM ${table} WHERE tenant_id = '${tenantA}'::uuid`));
        }),
        '42501',
      );
      await expectPgRejection(
        inTenant(tenantA, async (tx) => {
          await tx.execute(sql.raw(`TRUNCATE ${table}`));
        }),
        '42501',
      );
    }
  });

  it('context A: a cross-tenant parent is rejected by the composite FK (23503)', async () => {
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`INSERT INTO hall_terminals (id, tenant_id, hall_id, name, name_key)
              VALUES (${uuidv7()}, ${tenantA}, ${hallB}, 'Cross', ${`cross-t-${uuidv7()}`})`,
        );
      }),
      '23503',
    );
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`INSERT INTO loader_types (id, tenant_id, group_id, name, name_key)
              VALUES (${uuidv7()}, ${tenantA}, ${groupB}, 'Cross', ${`cross-lt-${uuidv7()}`})`,
        );
      }),
      '23503',
    );
  });

  it('context A: a duplicate live key in the same tenant is 23505, not a cross-tenant leak', async () => {
    await expectPgRejection(
      inTenant(tenantA, async (tx) => {
        await tx.execute(
          sql`INSERT INTO destinations (id, tenant_id, name, name_key)
              VALUES (${uuidv7()}, ${tenantA}, 'Dup', 'dest a')`,
        );
      }),
      '23505',
    );
  });
});
