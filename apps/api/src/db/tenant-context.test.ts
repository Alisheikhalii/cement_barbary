import { describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { DomainError } from '../common/errors/domain-error.js';
import { runWithTenantTx, TenantContext } from './tenant-context.js';

const tick = (ms = 1): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe('TenantContext', () => {
  const ctx = new TenantContext();

  it('require() outside run() throws TENANT_CONTEXT_MISSING (500, generic message)', () => {
    let caught: unknown;
    try {
      ctx.require();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(DomainError);
    const err = caught as DomainError;
    expect(err.code).toBe('TENANT_CONTEXT_MISSING');
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe('خطای داخلی سرور رخ داد');
    expect(ctx.current()).toBeUndefined();
  });

  it('current() inside run() returns the scope and run() returns fn’s value', async () => {
    const tenantId = uuidv7();
    const carrierId = uuidv7();
    const value = await ctx.run({ tenantId, carrierId }, async () => {
      expect(ctx.current()).toEqual({ tenantId, carrierId });
      expect(ctx.require().tenantId).toBe(tenantId);
      return 42;
    });
    expect(value).toBe(42);
    // The store is cleared once the callback finishes.
    expect(ctx.current()).toBeUndefined();
  });

  it('rejects an invalid tenant or carrier UUID with BAD_INPUT before any SQL', async () => {
    await expect(ctx.run({ tenantId: 'not-a-uuid' }, async () => 'x')).rejects.toMatchObject({
      code: 'BAD_INPUT',
    });
    await expect(
      ctx.run({ tenantId: uuidv7(), carrierId: 'also-bad' }, async () => 'x'),
    ).rejects.toMatchObject({ code: 'BAD_INPUT' });
    expect(ctx.current()).toBeUndefined();
  });

  it('propagates the scope across await and Promise.all', async () => {
    const tenantId = uuidv7();
    await ctx.run({ tenantId }, async () => {
      await tick(5);
      expect(ctx.require().tenantId).toBe(tenantId);
      const ids = await Promise.all(
        [1, 2, 3].map(async () => {
          await tick(2);
          return ctx.require().tenantId;
        }),
      );
      for (const id of ids) {
        expect(id).toBe(tenantId);
      }
    });
  });

  it('keeps 50 parallel runs with different tenants isolated from each other', async () => {
    const ids = Array.from({ length: 50 }, () => uuidv7());
    const seen = await Promise.all(
      ids.map((tenantId, i) =>
        ctx.run({ tenantId }, async () => {
          await tick(i % 5); // interleave the runs
          return ctx.require().tenantId;
        }),
      ),
    );
    for (let i = 0; i < ids.length; i++) {
      expect(seen[i]).toBe(ids[i]);
    }
    expect(ctx.current()).toBeUndefined();
  });

  it('rejects a scope switch while a transaction is active, leaving the outer context intact', async () => {
    const tenantA = uuidv7();
    const tenantB = uuidv7();
    await ctx.run({ tenantId: tenantA }, async () => {
      // runWithTenantTx is TenantDb’s internal hook; a stub handle exercises the guard.
      await runWithTenantTx({ stub: 'tx' }, async () => {
        await expect(ctx.run({ tenantId: tenantB }, async () => 'x')).rejects.toMatchObject({
          code: 'TENANT_CONTEXT_MISSING',
        });
        await expect(
          ctx.run({ tenantId: tenantA, carrierId: uuidv7() }, async () => 'x'),
        ).rejects.toMatchObject({ code: 'TENANT_CONTEXT_MISSING' });
        // The outer context is unchanged and still active.
        expect(ctx.require().tenantId).toBe(tenantA);
        expect(ctx.require().carrierId).toBeUndefined();
      });
    });
  });
});
