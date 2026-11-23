import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { DomainError } from '../src/common/errors/domain-error.js';
import { AuditStore } from '../src/db/audit-store.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb } from '../src/db/tenant-db.js';
import { AuditWriter } from '../src/modules/audit/audit-writer.js';
import { UserRoleService } from '../src/modules/users/user-role.service.js';
import { UsersRepository } from '../src/modules/users/users.repository.js';
import { createTenant, createUser, makeAppPool, ownerPool, testPii } from './setup/db.js';

/**
 * Assign/revoke existence-oracle fix (F1-06 T06, D2) against real PostgreSQL.
 *
 * A nonexistent user, another tenant's user and a soft-deleted user must give
 * byte-identical results for BOTH operations, and a real change must write its
 * user.role.* audit row with before/after role sets in the same transaction.
 */

describe('UserRoleService (integration)', () => {
  const ctx = new TenantContext();
  let app: Pool;
  let tenantA: string;
  let tenantB: string;
  let liveUser: string;
  let concurrentUser: string;
  let otherTenantUser: string;
  let deletedUser: string;
  let service: UserRoleService;

  beforeAll(async () => {
    const owner = ownerPool();
    tenantA = await createTenant(owner, `role-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(owner, `role-b-${uuidv7().slice(0, 8)}`);
    liveUser = await createUser(owner, tenantA, { username: 'role.live' });
    concurrentUser = await createUser(owner, tenantA, { username: 'role.concurrent' });
    otherTenantUser = await createUser(owner, tenantB, { username: 'role.other' });
    deletedUser = await createUser(owner, tenantA, { username: 'role.deleted' });
    await owner.query('UPDATE users SET deleted_at = now() WHERE id = $1', [deletedUser]);

    app = makeAppPool();
    const tenantDb = new TenantDb(drizzle(app, { schema }));
    const users = new UsersRepository(tenantDb, ctx, testPii());
    const audit = new AuditWriter(ctx, testPii(), new AuditStore(tenantDb));
    service = new UserRoleService(tenantDb, users, audit);
  });

  afterAll(async () => {
    await app.end();
  });

  function asTenant<T>(fn: () => Promise<T>): Promise<T> {
    return ctx.run({ tenantId: tenantA }, fn);
  }

  async function capture(promise: Promise<unknown>): Promise<Record<string, unknown>> {
    return promise.then(
      () => ({ resolved: true }),
      (error: unknown) => {
        if (!(error instanceof DomainError)) {
          return { name: error instanceof Error ? error.name : 'unknown' };
        }
        return {
          name: error.name,
          statusCode: error.statusCode,
          code: error.code,
          message: error.message,
          details: error.details ?? null,
        };
      },
    );
  }

  function auditRows(userId: string) {
    return ownerPool()
      .query<{
        action: string;
        actor_type: string;
        before: unknown;
        after: unknown;
        metadata: unknown;
      }>(
        `SELECT action, actor_type, before, after, metadata
           FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2 ORDER BY occurred_at`,
        [tenantA, userId],
      )
      .then((result) => result.rows);
  }

  it('gives the identical generic 404 for every invisible user, on both operations', async () => {
    const invisible = [
      uuidv7(), // nonexistent
      otherTenantUser, // exists in another tenant (RLS hides it)
      deletedUser, // soft-deleted in this tenant
    ];
    for (const userId of invisible) {
      const assigned = await capture(
        asTenant(() =>
          service.assign(userId, 'FACTORY_OPERATOR', { type: 'system', tool: 'test' }),
        ),
      );
      const revoked = await capture(
        asTenant(() =>
          service.revoke(userId, 'FACTORY_OPERATOR', { type: 'system', tool: 'test' }),
        ),
      );
      expect(assigned).toEqual({
        name: 'DomainError',
        statusCode: 404,
        code: 'NOT_FOUND',
        message: 'مسیر مورد نظر یافت نشد',
        details: null,
      });
      expect(revoked).toEqual(assigned);
    }
  });

  it('rejects an invalid role code with 400 for every user state (no second oracle)', async () => {
    const badInput = {
      name: 'DomainError',
      statusCode: 400,
      code: 'BAD_INPUT',
      message: 'ورودی نامعتبر است',
      details: null,
    };
    for (const userId of [liveUser, otherTenantUser, deletedUser, uuidv7()]) {
      const assigned = await capture(
        asTenant(() => service.assign(userId, 'NINJA', { type: 'system', tool: 'test' })),
      );
      const revoked = await capture(
        asTenant(() => service.revoke(userId, 'NINJA', { type: 'system', tool: 'test' })),
      );
      expect(assigned).toEqual(badInput);
      expect(revoked).toEqual(badInput);
    }
  });

  it('serializes two concurrent assigns: exactly one change and one row', async () => {
    const results = await Promise.all([
      asTenant(() =>
        service.assign(concurrentUser, 'CARRIER_ADMIN', { type: 'system', tool: 'test' }),
      ),
      asTenant(() =>
        service.assign(concurrentUser, 'CARRIER_ADMIN', { type: 'system', tool: 'test' }),
      ),
    ]);
    expect(results.map((result) => result.changed).sort()).toEqual([false, true]);
    const rows = await ownerPool().query<{ n: number }>(
      `SELECT count(*)::int AS n FROM audit_logs
        WHERE tenant_id = $1 AND resource_id = $2 AND action = 'user.role.assigned'
          AND after->'roles' ? 'CARRIER_ADMIN'`,
      [tenantA, concurrentUser],
    );
    expect(rows.rows[0]?.n).toBe(1);
  });

  it('assigns a role and writes user.role.assigned with before/after role sets', async () => {
    const result = await asTenant(() =>
      service.assign(liveUser, 'FACTORY_OPERATOR', { type: 'system', tool: 'test' }),
    );
    expect(result).toEqual({ changed: true, roles: ['FACTORY_OPERATOR'] });

    const rows = await auditRows(liveUser);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: 'user.role.assigned',
      actor_type: 'system',
      before: { roles: [] },
      after: { roles: ['FACTORY_OPERATOR'] },
      metadata: { tool: 'test', roleCode: 'FACTORY_OPERATOR' },
    });
  });

  it('does not write a row for an idempotent assign', async () => {
    const result = await asTenant(() =>
      service.assign(liveUser, 'FACTORY_OPERATOR', { type: 'system', tool: 'test' }),
    );
    expect(result.changed).toBe(false);
    expect(await auditRows(liveUser)).toHaveLength(1);
  });

  it('revokes a role and writes user.role.revoked with the reverse snapshots', async () => {
    const result = await asTenant(() =>
      service.revoke(liveUser, 'FACTORY_OPERATOR', { type: 'system', tool: 'test' }),
    );
    expect(result).toEqual({ changed: true, roles: [] });

    const rows = await auditRows(liveUser);
    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({
      action: 'user.role.revoked',
      actor_type: 'system',
      before: { roles: ['FACTORY_OPERATOR'] },
      after: { roles: [] },
    });
  });

  it('records a user actor with its session and no tool', async () => {
    await asTenant(() =>
      service.assign(liveUser, 'DRIVER', {
        type: 'user',
        userId: liveUser,
        sessionId: uuidv7(),
      }),
    );
    const rows = await auditRows(liveUser);
    const last = rows[rows.length - 1];
    expect(last?.metadata).toEqual({ roleCode: 'DRIVER' });
    const actor = await ownerPool().query<{ actor_type: string; actor_user_id: string }>(
      "SELECT actor_type, actor_user_id FROM audit_logs WHERE tenant_id = $1 AND action = 'user.role.assigned' AND actor_type = 'user'",
      [tenantA],
    );
    expect(actor.rows[0]?.actor_user_id).toBe(liveUser);
  });
});
