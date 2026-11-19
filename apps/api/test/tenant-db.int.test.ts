import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import { createTenant, makeAppPool, ownerPool } from './setup/db.js';

async function txidCurrent(tx: Tx): Promise<string> {
  const res = await tx.execute(sql`select txid_current()::text as id`);
  return (res.rows[0] as { id: string }).id;
}

/**
 * TenantDb against a real PostgreSQL 17 as the runtime role (bitabar_app).
 * The pool is capped at one connection so the no-leak test provably reuses
 * the same physical connection.
 */
describe('TenantDb (integration, runtime role)', () => {
  let pool: Pool;
  let tenantDb: TenantDb;
  const ctx = new TenantContext();
  let tenantA: string;
  let tenantB: string;

  beforeAll(async () => {
    pool = makeAppPool({ max: 1 });
    tenantDb = new TenantDb(drizzle(pool, { schema }));
    tenantA = await createTenant(ownerPool(), `t08-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(ownerPool(), `t08-b-${uuidv7().slice(0, 8)}`);
  });

  afterAll(async () => {
    await pool.end();
  });

  it('throws TENANT_CONTEXT_MISSING without a context and never acquires a connection', async () => {
    const fresh = makeAppPool({ max: 1 });
    try {
      const db = new TenantDb(drizzle(fresh, { schema }));
      await expect(db.run(async () => 'unreachable')).rejects.toMatchObject({
        code: 'TENANT_CONTEXT_MISSING',
      });
      expect(fresh.totalCount).toBe(0); // fail closed before any query is sent
    } finally {
      await fresh.end();
    }
  });

  it('without a context the runtime role sees zero rows (fail closed at the DB too)', async () => {
    const res = await pool.query('select id from tenants');
    expect(res.rows).toHaveLength(0);
  });

  it('pins app.current_tenant_id() to the scope inside the transaction', async () => {
    const seen = await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(async (tx) => {
        const res = await tx.execute(sql`select app.current_tenant_id() as id`);
        return (res.rows[0] as { id: string }).id;
      }),
    );
    expect(seen).toBe(tenantA);
  });

  it('sets app.carrier_id when scoped and NULL otherwise (nothing inherited)', async () => {
    const carrierId = uuidv7();
    const withCarrier = await ctx.run({ tenantId: tenantA, carrierId }, () =>
      tenantDb.run(async (tx) => {
        const res = await tx.execute(sql`select app.current_carrier_id() as id`);
        return (res.rows[0] as { id: string | null }).id;
      }),
    );
    expect(withCarrier).toBe(carrierId);

    const withoutCarrier = await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(async (tx) => {
        const res = await tx.execute(sql`select app.current_carrier_id() as id`);
        return (res.rows[0] as { id: string | null }).id;
      }),
    );
    expect(withoutCarrier).toBeNull();
  });

  it('does not leak the tenant setting to the pooled connection after commit', async () => {
    await ctx.run({ tenantId: tenantA }, () => tenantDb.run(async () => undefined));
    // pool.max = 1 → this query runs on the SAME physical connection:
    const res = await pool.query("select current_setting('app.tenant_id', true) as v");
    expect((res.rows[0] as { v: string }).v).toBe('');
  });

  it('sees only the scoped tenant’s rows (A cannot see B)', async () => {
    const ids = await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(async (tx) => {
        const res = await tx.execute(sql`select id from tenants`);
        return (res.rows as { id: string }[]).map((r) => r.id);
      }),
    );
    expect(ids).toEqual([tenantA]);
  });

  it('reuses the same transaction for a nested run with the same scope', async () => {
    const { outer, inner } = await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(async (tx) => {
        const outer = await txidCurrent(tx);
        const inner = await tenantDb.run(async (tx2) => txidCurrent(tx2));
        return { outer, inner };
      }),
    );
    expect(inner).toBe(outer);
  });

  it('rolls the transaction back when fn throws', async () => {
    const code = `t08-rb-${uuidv7().slice(0, 8)}`;
    const id = await createTenant(ownerPool(), code);
    await expect(
      ctx.run({ tenantId: id }, () =>
        tenantDb.run(async (tx) => {
          await tx.execute(sql`update tenants set name = 'CHANGED' where id = ${id}`);
          throw new Error('boom');
        }),
      ),
    ).rejects.toThrow('boom');
    const res = await ownerPool().query('select name from tenants where id = $1', [id]);
    expect((res.rows[0] as { name: string }).name).toBe(code);
  });

  it('applies the requested serializable isolation level', async () => {
    const level = await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(
        async (tx) => {
          const res = await tx.execute(sql`show transaction_isolation`);
          return (res.rows[0] as { transaction_isolation: string }).transaction_isolation;
        },
        { isolationLevel: 'serializable' },
      ),
    );
    expect(level).toBe('serializable');
  });

  it('rejects a tenant switch inside an active transaction and keeps the outer context', async () => {
    await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(async () => {
        await expect(ctx.run({ tenantId: tenantB }, async () => 'x')).rejects.toMatchObject({
          code: 'TENANT_CONTEXT_MISSING',
        });
        expect(ctx.require().tenantId).toBe(tenantA);
      }),
    );
  });
});
